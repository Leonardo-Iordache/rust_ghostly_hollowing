use std::time::Duration;
use reqwest::blocking::Client;

pub fn download_file(url: &str) -> Result<Vec<u8>, String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("[!] Failed to build client: {}", e))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("[!] Error downloading {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("Status: {}", response.status()));
    }

    let bytes = response
        .bytes()
        .map_err(|e| format!("[!] Failed to read bytes: {}", e))?;

    Ok(bytes.to_vec())
}



