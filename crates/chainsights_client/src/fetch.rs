// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use hickory_resolver::TokioResolver;
use sha2::{Digest, Sha256};

use crate::ArtifactLink;

//// Fetches the first line of a json lines (jsonl) Chainsights manifest from a given URL.
pub(crate) async fn fetch_manifest_text(url: &str) -> Result<String> {
    let resp = reqwest::get(url).await?.error_for_status()?;
    let body_text = resp.text().await?;
    let first_line = body_text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if first_line.is_empty() {
        bail!("Fetched manifest is empty");
    }
    Ok(first_line.to_string())
}

/// Parses a Chainsights PURL and extracts the domain, component name, and optional version.
pub(crate) async fn fetch_chainsights_info(domain_name: &str) -> Result<(String, String)> {
    let chainsights_domain = format!("_chainsights.{}", domain_name);
    println!("  Querying TXT record for: {}", chainsights_domain);
    let resolver = TokioResolver::builder_tokio()?.build();
    let txt_lookup = resolver.txt_lookup(&chainsights_domain).await?;
    for txt_record in txt_lookup.iter() {
        let combined_data = txt_record
            .txt_data()
            .iter()
            .map(|b| String::from_utf8_lossy(b))
            .collect::<Vec<_>>()
            .join("");
        if combined_data.contains("uri=") && combined_data.contains("identity=") {
            let mut uri = None;
            let mut identity = None;
            for part in combined_data.split_whitespace() {
                if let Some(u) = part.strip_prefix("uri=") {
                    uri = Some(u.trim_matches('"').to_string());
                } else if let Some(id) = part.strip_prefix("identity=") {
                    identity = Some(id.trim_matches('"').to_string());
                }
            }
            if let (Some(uri_val), Some(identity_val)) = (uri, identity) {
                if !uri_val.is_empty() && !identity_val.is_empty() {
                    return Ok((uri_val, identity_val));
                }
            }
        }
    }
    bail!("No valid chainsights TXT record for {}", chainsights_domain)
}

pub(crate) async fn fetch_and_verify_artifact(
    link: &ArtifactLink,
    client: &reqwest::Client,
) -> Result<Vec<u8>> {
    // (i) Fetch Artifact Content
    let response = client
        .get(&link.uri)
        .send()
        .await
        .with_context(|| format!("Failed to send request to artifact URI '{}'", link.uri))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to fetch artifact from URI '{}': HTTP Status {}",
            link.uri,
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("Failed to read artifact bytes from URI '{}'", link.uri))?
        .to_vec(); // Collect bytes into a Vec<u8>

    // (ii) Calculate Hash & (iii) Compare Hashes
    // Currently supports only sha256, but extensible via the HashMap
    // This is mostly only useful for non-signed artifacts.
    if let Some(expected_sha256_hex) = link.digest.as_ref().and_then(|digest| digest.get("sha256"))
    {
        if expected_sha256_hex.is_empty() {
            return Err(anyhow!(
                "Empty expected sha256 digest provided for URI '{}'",
                link.uri
            ));
        }

        let mut hasher = Sha256::new(); // [16]
        hasher.update(&bytes); // [16]
        let calculated_hash = hasher.finalize(); // [16]

        // Convert calculated hash to lowercase hex string [18]
        let calculated_sha256_hex = hex::encode(calculated_hash);

        // Compare (case-insensitive recommended for robustness)
        if !calculated_sha256_hex.eq_ignore_ascii_case(expected_sha256_hex) {
            return Err(anyhow!(
                "Digest mismatch for URI '{}'. Expected sha256: {}, Calculated: {}",
                link.uri,
                expected_sha256_hex,
                calculated_sha256_hex
            ));
        }
        println!("SHA256 verified for: {}", link.uri); // Log success
    } else {
        // Behavior if no sha256 digest is provided:
        // Option 1: Fail - require at least one known digest
        // return Err(anyhow!("No 'sha256' digest found in MetadataLink for URI '{}'. Cannot verify integrity.", link.uri));
        // Option 2: Warn and proceed (less secure)
        eprintln!(
            "Warning: No sha256 digest provided for URI '{}'. Skipping integrity check.",
            link.uri
        );
    }

    Ok(bytes)
}