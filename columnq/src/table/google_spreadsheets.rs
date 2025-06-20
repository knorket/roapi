use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::LazyLock;

use datafusion::arrow::array::{ArrayRef, BooleanArray, PrimitiveArray, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::datatypes::{Float64Type, Int64Type};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::TableProvider;
use regex::Regex;
use reqwest::Client;
use serde_derive::Deserialize;
use snafu::prelude::*;
use uriparse::URIReference;

use crate::table::{self, LoadedTable, TableOptionGoogleSpreadsheet, TableSource};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to build http client: {source}"))]
    BuildHttpClient { source: reqwest::Error },
    #[snafu(display("Failed to send API request: {source}"))]
    SendRequest { source: reqwest::Error },
    #[snafu(display("Expect int64 value, got: {value}"))]
    ExpectI64 { value: String },
    #[snafu(display("Expect float64 value, got: {value}"))]
    ExpectFloat64 { value: String },
    #[snafu(display("Failed to create record batch"))]
    CreateRecordBatch {
        source: datafusion::arrow::error::ArrowError,
    },
    #[snafu(display("Failed to read applicatin secret from disk: {source}"))]
    ReadAppSecret { source: std::io::Error },
    #[snafu(display("Failed to build service account authenticator: {source}"))]
    BuildAuthenticator { source: std::io::Error },
    #[snafu(display("Failed to obtain Oauth2 token: {source}"))]
    ObtainToken { source: yup_oauth2::Error },
    #[snafu(display("Oauth2 token not found"))]
    EmptyToken {},
    #[snafu(display("Failed to resolve sheet title: {source}"))]
    ResolveTitle { source: reqwest::Error },
    #[snafu(display("Failed to parse API response: {source}"))]
    ParseApiResp { source: reqwest::Error },
    #[snafu(display("Failed to load sheet value from API: {source}"))]
    HttpStatus { source: reqwest::Error },
    #[snafu(display("Googlesheet is empty"))]
    EmptySheet {},
    #[snafu(display("Invalid sheet id: {id}"))]
    InvalidSheetId { id: String },
    #[snafu(display("Invalid URI: {uri}"))]
    InvalidUri { uri: String },
}

// steps
// * Activate the Google Sheets API in the Google API Console.
//
// * Create service account: https://console.developers.google.com/apis/api/sheets.googleapis.com/credentials?project=roapi-302505
// * create key and save the json format somewhere safe
// * Share spreadsheet with service account

#[derive(Deserialize, Debug)]
struct SheetProperties {
    #[serde(rename = "sheetId")]
    sheet_id: usize,
    title: String,
    index: usize,
    // other unused attributes:
    //
    //   "sheetType": "GRID",
    //   "gridProperties": {
    //     "rowCount": 1000,
    //     "columnCount": 28
    //   }
    //
    // see: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/sheets#SheetProperties
}

#[derive(Deserialize, Debug)]
struct Sheet {
    properties: SheetProperties,
    // for all available fields, see:
    // https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets#Spreadsheet
}

#[derive(Deserialize, Debug)]
struct Spreadsheets {
    sheets: Vec<Sheet>,
    // other unused attributes:
    // * spreadsheetId
    // * properties
    // * spreadsheetUrl
    //
    // see: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct SpreadsheetValues {
    range: String,
    #[serde(rename = "majorDimension")]
    major_dimension: String,
    values: Vec<Vec<String>>,
}

// TODO: should we support optional column?
fn infer_value_type(v: &str) -> DataType {
    // match order matters
    match v {
        // TODO: support Date64 and Time64
        _ if v.parse::<i64>().is_ok() => DataType::Int64,
        _ if v.parse::<f64>().is_ok() => DataType::Float64,
        _ => match v.to_lowercase().as_str() {
            "false" | "true" => DataType::Boolean,
            _ => DataType::Utf8,
        },
    }
}

// util wrapper for calling google spreadsheet API
async fn gs_api_get(token: &str, url: &str) -> Result<reqwest::Response, Error> {
    Client::builder()
        .build()
        .context(BuildHttpClientSnafu)?
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .context(SendRequestSnafu)
}

fn coerce_type(l: DataType, r: DataType) -> DataType {
    match (l, r) {
        (DataType::Boolean, DataType::Boolean) => DataType::Boolean,
        (DataType::Date32, DataType::Date32) => DataType::Date32,

        (DataType::Date64, DataType::Date64)
        | (DataType::Date64, DataType::Date32)
        | (DataType::Date32, DataType::Date64) => DataType::Date64,

        (DataType::Int64, DataType::Int64) => DataType::Int64,

        (DataType::Float64, DataType::Float64)
        | (DataType::Float64, DataType::Int64)
        | (DataType::Int64, DataType::Float64) => DataType::Float64,

        _ => DataType::Utf8,
    }
}

fn infer_schema(rows: &[Vec<String>]) -> Schema {
    let mut col_types: HashMap<&str, HashSet<DataType>> = HashMap::new();

    let col_names = &rows[0];

    rows.iter().skip(1).for_each(|row| {
        row.iter().enumerate().for_each(|(i, col_val)| {
            let col_name = &col_names[i];
            let col_type = infer_value_type(col_val);
            let entry = col_types.entry(col_name).or_default();
            entry.insert(col_type);
        });
    });

    let fields: Vec<Field> = col_names
        .iter()
        .map(|col_name| {
            let set = col_types.entry(col_name).or_insert_with(|| {
                // TODO: this should never happen, maybe we should use panic instead?
                let mut set = HashSet::new();
                set.insert(DataType::Utf8);
                set
            });

            let mut dt_iter = set.iter().cloned();
            let dt_init = dt_iter.next().unwrap_or(DataType::Utf8);
            let dt = dt_iter.fold(dt_init, coerce_type);

            // normalize column name by replacing space with under score
            Field::new(col_name.replace(' ', "_"), dt, true)
        })
        .collect();
    Schema::new(fields)
}

fn parse_boolean(s: &str) -> bool {
    s.eq_ignore_ascii_case("true")
}

fn sheet_values_to_record_batch(values: &[Vec<String>]) -> Result<RecordBatch, Error> {
    let schema = infer_schema(values);

    let arrays = schema
        .fields()
        .iter()
        .enumerate()
        .map(|(i, field)| {
            // skip header row
            let rows_iter = values.iter().skip(1);

            Ok(match field.data_type() {
                DataType::Boolean => Arc::new(
                    rows_iter
                        .map(|row| row.get(i).map(|v| parse_boolean(v)))
                        .collect::<BooleanArray>(),
                ) as ArrayRef,
                DataType::Int64 => Arc::new(
                    rows_iter
                        .map(|row| {
                            row.get(i)
                                .map(|v| {
                                    v.parse::<i64>().map_err(|_| Error::ExpectI64 {
                                        value: row[i].clone(),
                                    })
                                })
                                .transpose()
                        })
                        .collect::<Result<PrimitiveArray<Int64Type>, Error>>()?,
                ) as ArrayRef,
                DataType::Float64 => Arc::new(
                    rows_iter
                        .map(|row| {
                            row.get(i)
                                .map(|v| {
                                    v.parse::<f64>().map_err(|_| Error::ExpectFloat64 {
                                        value: row[i].clone(),
                                    })
                                })
                                .transpose()
                        })
                        .collect::<Result<PrimitiveArray<Float64Type>, Error>>()?,
                ) as ArrayRef,

                _ => Arc::new(rows_iter.map(|row| row.get(i)).collect::<StringArray>()) as ArrayRef,
            })
        })
        .collect::<Result<Vec<ArrayRef>, Error>>()?;

    RecordBatch::try_new(Arc::new(schema), arrays).context(CreateRecordBatchSnafu)
}

async fn fetch_auth_token(
    opt: &TableOptionGoogleSpreadsheet,
) -> Result<yup_oauth2::AccessToken, Error> {
    // Read application creds from a file.The clientsecret file contains JSON like
    // `{"installed":{"client_id": ... }}`
    let creds = yup_oauth2::read_service_account_key(&opt.application_secret_path)
        .await
        .context(ReadAppSecretSnafu)?;

    let sa = yup_oauth2::ServiceAccountAuthenticator::builder(creds)
        .build()
        .await
        .context(BuildAuthenticatorSnafu)?;

    let scopes = &["https://www.googleapis.com/auth/spreadsheets.readonly"];

    sa.token(scopes).await.context(ObtainTokenSnafu)
}

async fn resolve_sheet_title(
    token: &str,
    spreadsheet_id: &str,
    uri: &URIReference<'_>,
) -> Result<String, Error> {
    // look up sheet title by sheet id through API
    let resp = gs_api_get(
        token,
        &format!("https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}"),
    )
    .await?
    .error_for_status()
    .context(ResolveTitleSnafu)?;

    let spreadsheets = resp
        .json::<Spreadsheets>()
        .await
        .context(ParseApiRespSnafu)?;

    // when sheet id is not specified from config, try to parse it from URI
    let sheet_id: Option<usize> = match uri.fragment() {
        // if sheeit id is specified within the URI in the format of #gid=x
        Some(fragment) => {
            let s = fragment.as_str();
            let parts: Vec<&str> = s.split('=').collect();
            match parts.len() {
                2 => match parts[0] {
                    "gid" => parts[1].parse().ok(),
                    _ => None,
                },
                _ => None,
            }
        }
        None => None,
    };

    let sheet = match sheet_id {
        Some(id) => spreadsheets
            .sheets
            .iter()
            .find(|s| s.properties.sheet_id == id)
            .ok_or_else(|| Error::InvalidSheetId { id: id.to_string() })?,
        // no sheet id specified, default to the first sheet
        None => spreadsheets
            .sheets
            .iter()
            .find(|s| s.properties.index == 0)
            .ok_or(Error::EmptySheet {})?,
    };

    Ok(sheet.properties.title.clone())
}

#[derive(Clone)]
struct GetReqContext {
    token: yup_oauth2::AccessToken,
    url: String,
}

static RE_GOOGLE_SHEET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https://docs.google.com/spreadsheets/d/(.+)").unwrap());

async fn gs_get_req_contex(t: &TableSource) -> Result<GetReqContext, table::Error> {
    let uri_str = t.get_uri_str();
    if RE_GOOGLE_SHEET.captures(uri_str).is_none() {
        return Err(Box::new(Error::InvalidUri {
            uri: uri_str.to_string(),
        }))
        .context(table::LoadGoogleSheetSnafu);
    }

    let uri = URIReference::try_from(uri_str)
        .map_err(Box::new)
        .context(table::InvalidUriReferenceSnafu)?;
    let spreadsheet_id = uri.path().segments()[2].as_str();

    let opt = t
        .option
        .as_ref()
        .ok_or(table::Error::MissingOption {})?
        .as_google_spreadsheet()?;

    let token = fetch_auth_token(opt)
        .await
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?;
    let token_str = token
        .token()
        .ok_or(Error::EmptyToken {})
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?;

    let sheet_title = match &opt.sheet_title {
        Some(t) => t.clone(),
        None => resolve_sheet_title(token_str, spreadsheet_id, &uri)
            .await
            .map_err(Box::new)
            .context(table::LoadGoogleSheetSnafu)?,
    };

    Ok(GetReqContext {
        token,
        url: format!(
            "https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/{sheet_title}"
        ),
    })
}

async fn to_mem_table(
    ctx: GetReqContext,
) -> Result<datafusion::datasource::MemTable, table::Error> {
    let token_str = ctx
        .token
        .token()
        .ok_or(Error::EmptyToken {})
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?;
    let resp = gs_api_get(token_str, &ctx.url)
        .await
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?
        .error_for_status()
        .context(HttpStatusSnafu)
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?;

    let sheet = resp
        .json::<SpreadsheetValues>()
        .await
        .context(ParseApiRespSnafu)
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?;

    let batch = sheet_values_to_record_batch(&sheet.values)
        .map_err(Box::new)
        .context(table::LoadGoogleSheetSnafu)?;
    let schema_ref = batch.schema();
    let partitions = vec![vec![batch]];

    datafusion::datasource::MemTable::try_new(schema_ref, partitions)
        .map_err(Box::new)
        .context(table::CreateMemTableSnafu)
}

pub async fn to_loaded_table(t: &TableSource) -> Result<LoadedTable, table::Error> {
    let ctx = gs_get_req_contex(t).await?;
    let to_datafusion_table = move || {
        let ctx = ctx.clone();
        async { Ok(Arc::new(to_mem_table(ctx).await?) as Arc<dyn TableProvider>) }
    };
    LoadedTable::new_from_df_table_cb(to_datafusion_table).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::Int64Array;

    fn row(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| s.to_string()).collect()
    }

    fn property_sheet() -> SpreadsheetValues {
        SpreadsheetValues {
            range: "Properties!A1:AB1000".to_string(),
            major_dimension: "ROWS".to_string(),
            values: vec![
                row(&[
                    "Address",
                    "Image",
                    "Landlord",
                    "Bed",
                    "Bath",
                    "Occupied",
                    "Monthly Rent",
                    "Lease Expiration Date",
                    "Days Until Expiration",
                ]),
                row(&[
                    "Bothell, WA",
                    "https://a.com/1.jpeg",
                    "Roger",
                    "3",
                    "2",
                    "FALSE",
                    "$2,000",
                    "10/23/2020",
                    "Expired",
                ]),
                row(&[
                    "Mill Creek, WA",
                    "https://a.com/2.jpeg",
                    "Sam",
                    "3",
                    "3",
                    "TRUE",
                    "$3,500",
                    "8/4/2021",
                    "193",
                ]),
                row(&[
                    "Fremont, WA",
                    "",
                    "Daniel",
                    "5",
                    "3",
                    "FALSE",
                    "$4,500",
                    "7/13/2019",
                    "Expired",
                ]),
                row(&[
                    "Shoreline, WA",
                    "https://a.com/3.jpeg",
                    "Roger",
                    "1",
                    "1",
                    "TRUE",
                    "$1,200",
                    "12/9/2021",
                    "320",
                ]),
            ],
        }
    }

    #[test]
    fn schema_inference() {
        let sheet = property_sheet();
        let schema = infer_schema(&sheet.values);
        assert_eq!(
            schema,
            Schema::new(vec![
                Field::new("Address", DataType::Utf8, true),
                Field::new("Image", DataType::Utf8, true),
                Field::new("Landlord", DataType::Utf8, true),
                Field::new("Bed", DataType::Int64, true),
                Field::new("Bath", DataType::Int64, true),
                Field::new("Occupied", DataType::Boolean, true),
                Field::new("Monthly_Rent", DataType::Utf8, true),
                Field::new("Lease_Expiration_Date", DataType::Utf8, true),
                Field::new("Days_Until_Expiration", DataType::Utf8, true),
            ])
        );
    }

    #[test]
    fn sheetvalue_to_record_batch() {
        let sheet = property_sheet();
        let batch = sheet_values_to_record_batch(&sheet.values).unwrap();

        assert_eq!(batch.num_columns(), 9);
        assert_eq!(
            batch.column(3).as_ref(),
            Arc::new(Int64Array::from(vec![3, 3, 5, 1])).as_ref(),
        );
        assert_eq!(
            batch.column(5).as_ref(),
            Arc::new(BooleanArray::from(vec![false, true, false, true])).as_ref(),
        );
        assert_eq!(
            batch.column(2).as_ref(),
            Arc::new(StringArray::from(vec!["Roger", "Sam", "Daniel", "Roger"])).as_ref(),
        );
    }

    #[test]
    fn unaligned_sheetvalue_to_record_batch() {
        // empty cells at the end of a row will not be returned from the server
        let sheet = SpreadsheetValues {
            range: "Properties!A1:AB1000".to_string(),
            major_dimension: "ROWS".to_string(),
            values: vec![
                row(&[
                    "Address",
                    "Image",
                    "Landlord",
                    "Bed",
                    "Bath",
                    "Occupied",
                    "Monthly Rent",
                    "Lease Expiration Date",
                    "Days Until Expiration",
                ]),
                row(&[
                    "Bothell, WA",
                    "https://a.com/1.jpeg",
                    "Roger",
                    "3",
                    "2",
                    "FALSE",
                    "$2,000",
                    "10/23/2020",
                    "Expired",
                ]),
                row(&[
                    "Shoreline, WA",
                    "https://a.com/3.jpeg",
                    "Roger",
                    "1",
                    "1",
                    "TRUE",
                    "$1,200",
                ]),
            ],
        };

        let batch = sheet_values_to_record_batch(&sheet.values).unwrap();

        assert_eq!(batch.num_columns(), 9);
        assert_eq!(
            batch.column(3).as_ref(),
            Arc::new(Int64Array::from(vec![3, 1])).as_ref(),
        );
        assert_eq!(
            batch.column(5).as_ref(),
            Arc::new(BooleanArray::from(vec![false, true])).as_ref(),
        );
        assert_eq!(
            batch.column(2).as_ref(),
            Arc::new(StringArray::from(vec!["Roger", "Roger"])).as_ref(),
        );
        assert_eq!(
            batch.column(8).as_ref(),
            Arc::new(StringArray::from(vec![Some("Expired"), None])).as_ref(),
        );
    }
}
