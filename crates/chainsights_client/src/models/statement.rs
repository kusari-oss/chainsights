// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Represents the in-toto statement structure.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InTotoStatement {
    #[serde(rename = "_type")]
    _type: String,
    subject: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

// TODO: Support the entire resource descriptor
/// This is a simplified ResourceDescriptor for the subject of the in-toto statement.
#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Subject {
    name: Option<String>,
    uri: Option<String>,
    // TODO: We currently ignore this, but we should verify it.
    digest: HashMap<String, String>,
}
