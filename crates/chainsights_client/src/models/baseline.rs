// SPDX-License-Identifier: Apache-2.0

// TODO: These structs should probably be in a separate crate, as they're not specific to Chainsights.
// NOTE: This isn't currently used, but we may want to use it in the future.

use serde::{Deserialize, Serialize};

/// Represents the OpenSSF Baseline predicate, which includes information about the verification process.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BaselinePredicate {
    /// The timestamp when this attestation was generated.
    pub verified_timestamp: String,
    /// Information about the Baseline verifier
    pub verifier: BaselineVerifier,
    /// Comment about the assessment. This is a free-form text field.
    pub assessment_comment: String,
    /// The list of Baseline controls and their implementation status.
    pub controls: Vec<BaselineControl>,
}

/// Represents the verifier information, including its ID and optional comment.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BaselineVerifier {
    /// The ID of the verifier (e.g., "email@example.com").
    pub id: String,
    /// Optional comment about the verifier.
    pub comment: Option<String>,
}

/// Represents a control in the OpenSSF Baseline, including its name, implementation status, and optional evidence.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BaselineControl {
    /// The id of the control (e.g., "OSPS-123").
    pub control: String,
    /// Whether or not the control is implemented.
    pub implemented: bool,
    /// Optional evidence for the control.
    pub evidence: Option<Vec<BaselineEvidence>>,
}

/// Represents evidence for a control, including its description, URI, and media type.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BaselineEvidence {
    /// Optional description of the evidence.
    pub description: Option<String>,
    /// Optional URI link to the evidence.
    pub uri: Option<String>,
    /// Optional media type of the evidence (e.g., "application/vnd.in-toto+json").
    pub media_type: Option<String>,
}