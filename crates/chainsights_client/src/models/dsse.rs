// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Struct to hold the parsed Chainsights bundle data.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SigstoreBundleData {
    pub verification_material: VerificationMaterial,
    pub dsse_envelope: DsseEnvelope,
    // mediaType, timestampVerificationData, tlogEntries are ignored here. Long term, we may want to verify them.
}

/// Struct to hold the verification material data.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerificationMaterial {
    pub certificate: CertificateData,
    // tlogEntries, timestampVerificationData ignored
}

/// Struct to hold the certificate data.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateData {
    pub raw_bytes: String, // Base64 encoded DER certificate
}

/// Struct to hold the DSSE envelope data.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DsseEnvelope {
    pub payload: String,      // Base64 encoded payload (in-toto statement)
    pub payload_type: String, // e.g., application/vnd.in-toto+json
    pub signatures: Vec<SignatureData>,
}

/// Struct to hold the signature data.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignatureData {
    pub sig: String, // Base64 encoded signature
}