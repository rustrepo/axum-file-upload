/*

[dependencies]
axum = { version = "0.6", features = ["multipart"] }
tokio = { version = "1", features = ["full"] }
hyper = { version = "0.14", features = ["full"] }
tower = "0.4"

*/

use axum::{
    body::Body,
    extract::Multipart,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use std::{fs::create_dir_all, net::SocketAddr, path::PathBuf};
use tokio::{fs, io::AsyncWriteExt};

const UPLOAD_DIR: &str = "./uploads";

#[tokio::main]
async fn main() {
    // Ensure the upload directory exists
    create_dir_all(UPLOAD_DIR).expect("Failed to create upload directory");

    // Define routes
    let app = Router::new()
        .route("/", get(show_form))
        .route("/upload", post(upload_file));

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3030));
    println!("Server running at http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/// Handler to show the HTML form
async fn show_form() -> Html<&'static str> {
    Html(FORM_HTML)
}

/// Handler for file upload
async fn upload_file(mut multipart: Multipart) -> impl IntoResponse {
    let mut uploaded_files = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        if let Some(file_name) = field.file_name().map(|f| f.to_string()) {
            let file_path = PathBuf::from(UPLOAD_DIR).join(&file_name);

            if let Ok(data) = field.bytes().await {
                if let Ok(mut file) = fs::File::create(&file_path).await {
                    if file.write_all(&data).await.is_ok() {
                        uploaded_files.push(file_name);
                    }
                }
            }
        }
    }

    if uploaded_files.is_empty() {
        (StatusCode::BAD_REQUEST, "No files uploaded.".into())
    } else {
        (
            StatusCode::OK,
            format!("Files uploaded successfully: {:?}", uploaded_files),
        )
    }
}

const FORM_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
</head>
<body>
    <h1>Upload a File</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" multiple>
        <button type="submit">Upload</button>
    </form>
</body>
</html>
"#;
