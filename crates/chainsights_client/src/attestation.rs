// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigstore::cosign::{Client, CosignCapabilities};
use x509_parser::{parse_x509_certificate, prelude::GeneralName};

use crate::models::dsse::SigstoreBundleData;

// TODO: Don't bypass Rekor/Fulcio verification
/// Verifies the signature from a Sigstore bundle JSON by manually constructing
/// the PAE and using Client::verify_blob. Also checks identity.
/// NOTE: This bypasses Rekor/Fulcio verification.
pub(crate) fn verify_signature_with_pae(bundle_json_text: &str, expected_identity: &str) -> Result<Vec<u8>> {
    // 1. Parse the bundle JSON
    let bundle: SigstoreBundleData =
        serde_json::from_str(bundle_json_text).context("Failed to parse bundle JSON")?;
    println!("  Parsed essential bundle data.");

    // 2. Extract necessary components
    let cert_base64 = &bundle.verification_material.certificate.raw_bytes;
    let payload_base64 = &bundle.dsse_envelope.payload;
    let payload_type = &bundle.dsse_envelope.payload_type;
    let sig_base64 = bundle
        .dsse_envelope
        .signatures
        .get(0)
        .map(|s| &s.sig)
        .context("Bundle contains no signatures in dsseEnvelope")?;

    // 3. Decode Payload
    let payload_bytes = STANDARD
        .decode(payload_base64)
        .context("Failed to decode dsseEnvelope.payload")?;
    println!("  Decoded payload ({} bytes).", payload_bytes.len());

    // 4. Construct PAE (Pre-Authentication Encoding) data
    // PAE(type, payload) = "DSSEv1" SP len(type) SP type SP len(payload) SP payload
    let pae_data = construct_pae(&payload_type, &payload_bytes);
    println!("  Constructed PAE data ({} bytes).", pae_data.len());

    // 5. Prepare PEM Certificate String
    let cert_der_bytes = STANDARD
        .decode(cert_base64)
        .context("Failed to decode certificate rawBytes")?;
    let cert_pem_string = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        STANDARD.encode(&cert_der_bytes) // Re-encode DER bytes as base64 for PEM
    );
    println!("  Prepared PEM certificate string.");

    // 6. Verify signature using Client::verify_blob with PAE data
    println!("  Calling Client::verify_blob with PAE data...");
    Client::verify_blob(&cert_pem_string, sig_base64, &pae_data)
        .context("Signature verification failed using verify_blob with PAE data")?;
    println!("  Cryptographic signature verified successfully!");

    // 7. Verify Identity (Certificate SAN Check) - Reuse function from previous step
    // Pass the DER bytes directly to avoid re-decoding
    inspect_certificate_identity_from_der(&cert_der_bytes, expected_identity)
        .context("Certificate identity verification failed")?;
    println!("  Certificate identity verified successfully!");

    // 8. Return the original decoded payload bytes
    Ok(payload_bytes)
}

/// Helper function to construct DSSE v1 Pre-Authentication Encoding bytes.
fn construct_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = Vec::with_capacity(header.len() + payload.len());
    pae.extend_from_slice(header.as_bytes());
    pae.extend_from_slice(payload);
    pae
}

/// Helper function to inspect certificate identity directly from DER bytes.
/// (Adapted from previous `inspect_certificate_identity` function)
fn inspect_certificate_identity_from_der(
    cert_der_bytes: &[u8],
    expected_identity: &str,
) -> Result<()> {
    println!("  Inspecting certificate identity...");
    match parse_x509_certificate(cert_der_bytes) {
        Ok((_, cert)) => {
            let mut identity_found_in_san = false;
            match cert.subject_alternative_name() {
                Ok(Some(san)) => {
                    for name in &san.value.general_names {
                        if let GeneralName::RFC822Name(email) = name {
                            println!("    - Found email SAN: {}", email);
                            if email.eq_ignore_ascii_case(expected_identity) {
                                identity_found_in_san = true;
                                break;
                            }
                        }
                        // TODO: Handle other SAN types if needed. Currently unsure.
                    }
                }
                _ => println!("    - No SAN extension or failed to parse SAN."), // Handle None or Err
            }

            if identity_found_in_san {
                Ok(())
            } else {
                bail!(
                    "Expected identity '{}' not found in certificate SAN",
                    expected_identity
                )
            }
        }
        Err(e) => {
            bail!("Failed to parse X.509 certificate from DER: {}", e)
        }
    }
}