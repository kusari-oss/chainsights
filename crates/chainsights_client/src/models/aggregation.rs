// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::chainsights::{ArtifactLink, ChainsightsCatalogPredicate, ChainsightsComponentPredicate, ChainsightsReleasePredicate};

/// AggregatedCatalogData is the top-level structure for the aggregated Chainsights data output.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub(crate) struct AggregatedCatalogData {
    /// The root predicate parsed from the Chainsights catalog
    pub catalog_predicate: Option<ChainsightsCatalogPredicate>,
    /// The list of components aggregated from the catalog
    pub components: Vec<AggregatedComponentData>,
    /// Any errors encountered while processing the root URI
    pub root_error: Option<String>,
    /// Any errors encountered while processing component links
    pub component_errors: Vec<(String, String)>,
}

/// AggregatedComponentData contains the data for a single component, including its releases and any errors encountered.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub(crate) struct AggregatedComponentData {
    /// The component predicate parsed from following the link in a Chainsights catalog
    pub component_predicate: Option<ChainsightsComponentPredicate>,
    /// The list of releases aggregated from the component
    pub releases: Vec<AggregatedReleaseData>,
    /// The URI from which this component manifest was fetched
    pub component_link_uri: String,
    /// Any errors encountered while processing the release links
    pub release_errors: Vec<(String, String)>,
}

/// AggregatedReleaseData contains the data for a single release, including its artifacts and any errors encountered.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub(crate) struct AggregatedReleaseData {
    /// The release predicate parsed from following the link in the Chainsights component manifest
    pub release_predicate: Option<ChainsightsReleasePredicate>,
    /// The list of metadata artifacts linked from the release predicate (e.g. SBOM, SLSA attestation)
    pub metadata_artifacts: Vec<ArtifactLink>,
    /// The URI from which this release manifest was fetched
    pub release_link_uri: String,
    /// Any errors encountered while processing the artifact links
    pub artifact_fetch_errors: Vec<(String, String)>, // (URI, Error Message) for artifact fetching
}