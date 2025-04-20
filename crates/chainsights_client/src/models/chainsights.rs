// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::models::statement::InTotoStatement;

/// Represents a link to an attestation, including its URI, digest, media type, and expected signer identity.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttestationLink {
    /// URI of the attestation (e.g., "https://example.com/attestation.json").
    pub uri: String,
    /// Optional digest of the attestation (e.g., {"sha256": "..."}) This is useful for verifying unsigned artifacts.
    digest: Option<HashMap<String, String>>,
    /// Optional media type of the attestation (e.g., "application/vnd.in-toto+json").
    media_type: Option<String>,
    /// Optional expected identity for the attestation
    pub expected_signer_identity: String, 
}

/// Enum to hold the different parsed Chainsights predicate types.
#[derive(Deserialize, Serialize, Debug)]
pub(crate) enum ChainsightsPredicate {
    Catalog(ChainsightsCatalogPredicate),
    Component(ChainsightsComponentPredicate),
    Release(ChainsightsReleasePredicate),
    //Baseline(BaselinePredicate), // Added Baseline predicate type
    Unknown {
        predicate_type: String,
        predicate_value: serde_json::Value,
    },
}

/// Represents the Chainsights catalog predicate, which includes information about the catalog and its components.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainsightsCatalogPredicate {
    generator: Option<Generator>,
    /// The timestamp when this catalog was generated.
    timestamp: String,
    // TODO: Add sub_catalogs.
    /// List of components included in this catalog.
    pub components: Vec<CatalogComponentEntry>,
    /// Optional sub-catalogs (e.g., "sub-catalog" for a specific domain, or ).
    pub sub_catalogs: Option<Vec<SubCatalogLink>>,

    /// Optional Metadata links for the catalog itself. For example a SOC2 report.
    metadata_links: Option<Vec<ArtifactLink>>,
}

/// Represents a single component entry in the catalog.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CatalogComponentEntry {
    /// Human-readable name (e.g., "Awesome Web App", "Core Processing Library").
    name: String,
    /// Brief description of the component.
    description: Option<String>,
    /// Canonical PURL identifier for the component (typically versionless). REQUIRED.
    component_purl: String,
    /// Link to the ChainsightsComponentPredicate bundle for this component. REQUIRED.
    pub component_attestation_link: AttestationLink,
    /// Optional key-value labels for categorization/filtering.
    labels: Option<HashMap<String, String>>,
}

/// Represents a link to a sub-catalog, including its name and attestation link.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubCatalogLink {
    /// Human-readable name of the sub-catalog.
    name: String,
    /// Link to the ChainsightsCatalogPredicate bundle for this sub-catalog. REQUIRED.
    catalog_attestation_link: AttestationLink,
}

/// Represents a Chainsights component predicate, which includes information about the component and its repositories.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainsightsComponentPredicate {
    /// Optional generator information for the predicate.
    generator: Option<Generator>,
    /// Timestamp when this attestation was generated.
    timestamp: String,
    /// Canonical PURL matching the one in the Catalog. REQUIRED.
    purl: String,
    /// Human-readable name of the component (e.g., "Awesome Web App", "Core Processing Library"). REQUIRED.
    pub name: String,
    /// Optional human-readable description of the component.
    description: Option<String>,
    /// Other names or identifiers this component might be known by.
    aliases: Option<Vec<String>>,
    /// Optional key-value labels for categorization.
    labels: Option<HashMap<String, String>>,

    // --- Repository & Source Information ---
    /// List of repositories contributing code or artifacts to this component.
    repositories: Vec<RepositoryInfo>,

    // --- Hierarchy Links ---
    /// Links to finer-grained sub-components, if applicable (e.g., microservices within a SaaS product).
    sub_components: Option<Vec<SubComponentLink>>,
    /// Links to ChainsightsReleasePredicate bundles for specific versions of this component.
    /// Potentially ordered (e.g., most recent first), though order isn't guaranteed by the structure itself.
    pub release_attestations: Vec<AttestationLink>,

    /// Optional metadata links for the component itself (e.g., Baseline).
    metadata_links: Option<Vec<ArtifactLink>>,
}

/// Represents a repository contributing to the component, including its type, URI, and paths.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryInfo {
    /// Type of repository (e.g., "git", "svn", "oci").
    repo_type: String,
    /// The primary URI of the repository (e.g., git clone URL). REQUIRED.
    uri: String,
    /// Specific paths within the repository relevant to this component.
    /// Used for monorepo support. E.g., ["/services/auth", "/libs/shared"]
    paths: Option<Vec<String>>,
    /// The primary or root path for the component within the repo, if applicable.
    primary_path: Option<String>,
}

/// Represents a link to a sub-component, including its PURL and attestation link.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubComponentLink {
    /// Human-readable name of the sub-component.
    name: String,
    /// PURL for the sub-component. REQUIRED.
    sub_component_purl: String,
    /// Link to the sub-component's own ChainsightsComponentPredicate bundle. REQUIRED.
    component_attestation_link: AttestationLink,
}

/// A predicate for a specific release of a component.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainsightsReleasePredicate {
    /// Optional generator information for the predicate.
    generator: Option<Generator>,
    /// Timestamp when this attestation was generated.
    timestamp: String,

    // --- Release Identification & Metadata ---
    /// PURL of the component. REQUIRED.
    pub purl: String,
    /// Human-readable name of the release (e.g., "v1.2.0", "2023-10-01").
    name: String,
    /// ISO 8601 date when this version was released.
    release_date: Option<String>,
    /// Optional link to human-readable release notes.
    release_notes_uri: Option<String>,
    /// Optional indicator of the release's maturity (e.g., "development", "beta", "stable", "deprecated").
    lifecycle_phase: Option<String>,

    // --- Linked Artifacts ---
    /// Links to associated supply chain artifacts (SBOMs, SLSA, VEX, etc.). REQUIRED.
    pub metadata_links: Option<Vec<ArtifactLink>>,

    /// List of artifacts associated with this release.
    artifacts: Option<Vec<ArtifactLink>>,
}

/// Represents the generator of the predicate, typically a tool or service.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Generator {
    purl: String,
}

// TODO: Split ArtifactLink into signed and unsigned versions.
/// Represents a link to an artifact, including optional metadata for verification.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactLink {
    /// URI of the artifact (e.g., "https://example.com/artifact.json").
    pub uri: String,
    /// Optional digest of the artifact (e.g., {"sha256": "..."}) This is useful for verifying unsigned artifacts.
    pub digest: Option<HashMap<String, String>>,
    /// Optional media type of the artifact (e.g., "application/vnd.in-toto+json").
    pub media_type: Option<String>,
    /// Optional expected identity for the artifact
    pub expected_signer_identity: Option<String>,
}

// TODO: Figure out if Baseline will be a first class predicate type or not.
/// Parses the predicate from an InTotoStatement based on its predicateType.
pub(crate) fn parse_predicate(statement: &InTotoStatement) -> Result<ChainsightsPredicate> {
    const CATALOG_V1: &str = "https://chainsights.rest/catalog/v1";
    const COMPONENT_V1: &str = "https://chainsights.rest/component/v1";
    const RELEASE_V1: &str = "https://chainsights.rest/release/v1";
    // const BASELINE: &str = "https://baseline.openssf.org/attestation/manual";

    match statement.predicate_type.as_str() {
        CATALOG_V1 => {
            let predicate: ChainsightsCatalogPredicate =
                serde_json::from_value(statement.predicate.clone())
                    .context(format!("Failed to parse predicate as {}", CATALOG_V1))?;
            Ok(ChainsightsPredicate::Catalog(predicate))
        }
        COMPONENT_V1 => {
            let predicate: ChainsightsComponentPredicate =
                serde_json::from_value(statement.predicate.clone())
                    .context(format!("Failed to parse predicate as {}", COMPONENT_V1))?;
            Ok(ChainsightsPredicate::Component(predicate))
        }
        RELEASE_V1 => {
            let predicate: ChainsightsReleasePredicate =
                serde_json::from_value(statement.predicate.clone())
                    .context(format!("Failed to parse predicate as {}", RELEASE_V1))?;
            Ok(ChainsightsPredicate::Release(predicate))
        }
        /*BASELINE => {
            let predicate: BaselinePredicate = serde_json::from_value(statement.predicate.clone())
               .context(format!("Failed to parse predicate as {}", BASELINE))?;
            Ok(ChainsightsPredicate::Baseline(predicate))
        }*/
        unknown_type => {
            println!("WARN: Unrecognized predicateType: {}", unknown_type);
            Ok(ChainsightsPredicate::Unknown {
                predicate_type: unknown_type.to_string(),
                predicate_value: statement.predicate.clone(),
            })
        }
    }
}