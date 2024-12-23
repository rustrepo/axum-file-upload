/*
[dependencies]
axum = { version = "0.6", features = ["multipart"] }
tokio = { version = "1", features = ["full"] }
hyper = { version = "0.14", features = ["full"] }
tower = "0.4"
reqwest = { version = "0.11", features = ["json"] }
chrono = "0.4"
hmac = "0.12"
sha2 = "0.10"
urlencoding = "2.1"
dotenv = "0.15"
walkdir = "2.3"
hex = "0.4"
*/

use axum::{
    body::Body,
    extract::Multipart,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use reqwest::{Client, header::{HeaderMap, HeaderValue, CONTENT_TYPE}};
use sha2::{Digest, Sha256};
use std::{env, fs::create_dir_all, net::SocketAddr, path::{Path, PathBuf}};
use tokio::{fs, io::AsyncWriteExt};
use urlencoding::encode;

type HmacSha256 = Hmac<Sha256>;

const UPLOAD_DIR: &str = "./uploads";

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Ensure the upload directory exists
    create_dir_all(UPLOAD_DIR).expect("Failed to create upload directory");

    // Define routes
    let app = Router::new()
        .route("/", get(show_form))
        .route("/upload", post(handle_upload));

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3030));
    println!("Server running at http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/// HTML Form to upload files
async fn show_form() -> Html<&'static str> {
    Html(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Upload Files</title>
    </head>
    <body>
        <h1>Upload Files</h1>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" multiple>
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    "#)
}

/// Handle file uploads and upload to S3
async fn handle_upload(mut multipart: Multipart) -> impl IntoResponse {
    let client = Client::new();

    // AWS credentials and bucket info
    let bucket_name = env::var("BUCKET_NAME").unwrap_or_else(|_| "your-bucket-name".to_string());
    let region = env::var("AWS_REGION").unwrap_or_else(|_| "your-region".to_string());
    let access_key = env::var("AWS_ACCESS_KEY").unwrap_or_else(|_| "your-access-key".to_string());
    let secret_key = env::var("AWS_SECRET_KEY").unwrap_or_else(|_| "your-secret-key".to_string());

    let date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_short = &date[..8];
    let signing_key = get_signature_key(&secret_key, date_short, &region, "s3");

    let mut uploaded_files = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        if let Some(file_name) = field.file_name().map(|f| f.to_string()) {
            let file_path = PathBuf::from(UPLOAD_DIR).join(&file_name);

            if let Ok(data) = field.bytes().await {
                // Save file locally
                if let Ok(mut file) = fs::File::create(&file_path).await {
                    if file.write_all(&data).await.is_ok() {
                        uploaded_files.push(file_name.clone());

                        // Upload to S3
                        if let Err(e) = upload_file_to_s3_async(
                            &file_path,
                            &bucket_name,
                            &region,
                            &access_key,
                            &secret_key,
                            &client,
                            &signing_key,
                            &date,
                            date_short,
                        ).await {
                            eprintln!("Failed to upload {}: {}", file_name, e);
                        }
                    }
                }
            }
        }
    }

    if uploaded_files.is_empty() {
        (StatusCode::BAD_REQUEST, "No files uploaded.".to_string())
    } else {
        (
            StatusCode::OK,
            format!("Files uploaded successfully: {:?}", uploaded_files),
        )
    }
    
}

/// Upload file to S3 asynchronously
async fn upload_file_to_s3_async(
    file_path: &Path,
    bucket_name: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    client: &Client,
    signing_key: &[u8],
    date: &str,
    date_short: &str,
) -> Result<String, String> {
    let file_name = file_path
        .file_name()
        .ok_or_else(|| "Invalid file name".to_string())?
        .to_string_lossy()
        .to_string();

    if file_name == ".DS_Store" {
        return Ok("File ignored: .DS_Store".to_string());
    }

    let encoded_file_name = encode(&file_name);
    let new_file_name = format!("{}-{}", date, encoded_file_name);

    let content = fs::read(file_path)
        .await
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let host = format!("{}.s3.{}.amazonaws.com", bucket_name, region);
    let endpoint = format!("https://{}/{}", host, new_file_name);

    let canonical_headers = format!("host:{}\nx-amz-date:{}\n", host, date);
    let signed_headers = "host;x-amz-date";
    let payload_hash = hex::encode(Sha256::digest(&content));
    let canonical_request = format!(
        "PUT\n/{}\n\n{}\n{}\n{}",
        new_file_name, canonical_headers, signed_headers, payload_hash
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{}/{}/{}/aws4_request", date_short, region, "s3");
    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        algorithm, date, credential_scope, canonical_request_hash
    );

    let signature = {
        let mut mac = HmacSha256::new_from_slice(signing_key).unwrap();
        mac.update(string_to_sign.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };

    let authorization_header = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        algorithm, access_key, credential_scope, signed_headers, signature
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-amz-date", HeaderValue::from_str(date).unwrap());
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert("Authorization", HeaderValue::from_str(&authorization_header).unwrap());
    headers.insert("x-amz-content-sha256", HeaderValue::from_str(&payload_hash).unwrap());

    let response = client
        .put(&endpoint)
        .headers(headers)
        .body(content)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        Ok(format!("File uploaded successfully: {}", new_file_name))
    } else {
        Err(format!(
            "Failed to upload file: {}. Status: {}",
            new_file_name,
            response.status()
        ))
    }
}

/// Generate the AWS signature key
fn get_signature_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = HmacSha256::new_from_slice(format!("AWS4{}", secret).as_bytes()).unwrap();
    key.update(date.as_bytes());
    let mut key = HmacSha256::new_from_slice(&key.finalize().into_bytes()).unwrap();
    key.update(region.as_bytes());
    let mut key = HmacSha256::new_from_slice(&key.finalize().into_bytes()).unwrap();
    key.update(service.as_bytes());
    let mut key = HmacSha256::new_from_slice(&key.finalize().into_bytes()).unwrap();
    key.update(b"aws4_request");
    key.finalize().into_bytes().to_vec()
}
