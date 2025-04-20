// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use crate::{attestation::verify_signature_with_pae, fetch::fetch_manifest_text, models::{self, statement::InTotoStatement}, AggregatedCatalogData, AggregatedComponentData, AggregatedReleaseData, ChainsightsPredicate};
use anyhow::{Context, Result};

// TODO: This should be configurable
const MAX_DEPTH: u32 = 10;

pub(crate) async fn traverse_and_aggregate(
    root_uri: &str,
    root_identity: &str,
) -> Result<AggregatedCatalogData> {
    // Can return Err on catastrophic failure (e.g., client creation)

    // (i) Initialization
    let client = reqwest::Client::new(); // Create client once
    // For sequential processing:
    let mut visited_uris = HashSet::new();
    // For concurrent processing with join_all (more complex):
    // let visited_uris = Arc::new(Mutex::new(HashSet::new()));

    let mut aggregated_data = AggregatedCatalogData::default();

    // (ii) Process Root URI
    match process_attestation_uri(root_uri, root_identity, &mut visited_uris, 0, &client).await {
        Ok(ChainsightsPredicate::Catalog(catalog)) => {
            aggregated_data.catalog_predicate = Some(catalog.clone()); // Store the root predicate

            // (iii) Recursive Traversal (Sequential Example)
            for component in &catalog.components {
                let component_uri = &component.component_attestation_link.uri;
                let component_identity = &component
                    .component_attestation_link
                    .expected_signer_identity;

                // Check visited state *before* recursive call (important for sequential)
                if visited_uris.contains(component_uri) {
                    aggregated_data.component_errors.push((
                        component_uri.clone(),
                        format!("Cycle detected: URI '{}' already visited", component_uri),
                    ));
                    continue; // Skip this component, proceed to the next
                }
                if 0 + 1 >= MAX_DEPTH {
                    // Check depth before call
                    aggregated_data.component_errors.push((
                        component_uri.clone(),
                        format!(
                            "Maximum traversal depth ({}) would be exceeded at URI '{}'",
                            MAX_DEPTH, component_uri
                        ),
                    ));
                    continue;
                }

                match process_attestation_uri(
                    component_uri,
                    component_identity,
                    &mut visited_uris,
                    1,
                    &client,
                )
                .await
                {
                    Ok(ChainsightsPredicate::Component(component_predicate)) => {
                        let mut agg_comp_data = AggregatedComponentData {
                            component_predicate: Some(component_predicate.clone()),
                            component_link_uri: component_uri.clone(),
                            ..Default::default()
                        };

                        // Recursively process releases for this component
                        for release_link in &component_predicate.release_attestations {
                            let release_uri = &release_link.uri;
                            let release_identity = &release_link.expected_signer_identity;

                            if visited_uris.contains(release_uri) {
                                agg_comp_data.release_errors.push((
                                    release_uri.clone(),
                                    format!(
                                        "Cycle detected: URI '{}' already visited",
                                        release_uri
                                    ),
                                ));
                                continue;
                            }
                            if 1 + 1 >= MAX_DEPTH {
                                agg_comp_data.release_errors.push((
                                    release_uri.clone(),
                                    format!("Maximum traversal depth ({}) would be exceeded at URI '{}'", MAX_DEPTH, release_uri)
                                ));
                                continue;
                            }

                            match process_attestation_uri(
                                release_uri,
                                release_identity,
                                &mut visited_uris,
                                2,
                                &client,
                            )
                            .await
                            {
                                Ok(ChainsightsPredicate::Release(release_predicate)) => {
                                    agg_comp_data.releases.push(AggregatedReleaseData {
                                        release_predicate: Some(release_predicate.clone()),
                                        metadata_artifacts: release_predicate
                                            .metadata_links
                                            .unwrap_or(Vec::new())
                                            .clone(), // Assuming artifacts are directly in predicate
                                        release_link_uri: release_uri.clone(),
                                        ..Default::default()
                                    });
                                }
                                Ok(other_pred) => {
                                    agg_comp_data.release_errors.push((
                                        release_uri.clone(),
                                        format!(
                                            "Expected Release predicate, found {:?}",
                                            other_pred
                                        ),
                                    ));
                                }
                                Err(e) => {
                                    agg_comp_data
                                        .release_errors
                                        .push((release_uri.clone(), e.to_string()));
                                }
                            }
                        }
                        aggregated_data.components.push(agg_comp_data);
                    }
                    Ok(other_pred) => {
                        aggregated_data.component_errors.push((
                            component_uri.clone(),
                            format!("Expected Component predicate, found {:?}", other_pred),
                        ));
                    }
                    Err(e) => {
                        aggregated_data
                            .component_errors
                            .push((component_uri.clone(), e.to_string()));
                    }
                }
            }
        }
        Ok(other_pred) => {
            // Root URI did not yield a Catalog predicate
            aggregated_data.root_error = Some(format!(
                "Expected Catalog predicate at root URI '{}', but found {:?}",
                root_uri, other_pred
            ));
            // Decide whether to return Ok or Err based on requirements. Returning Ok allows showing the error.
        }
        Err(e) => {
            // Failed to process the root URI itself
            aggregated_data.root_error =
                Some(format!("Failed to process root URI '{}': {}", root_uri, e));
            // Return Ok with the error stored, or return Err(e) to indicate total failure.
            // Returning Ok is consistent with aggregating errors.
        }
    }

    Ok(aggregated_data)
}

async fn process_attestation_uri(
    uri: &str,
    expected_identity: &str,
    visited_uris: &mut HashSet<String>,
    depth: u32,
    _client: &reqwest::Client,
) -> Result<ChainsightsPredicate> {
    if visited_uris.contains(uri) {
        return Err(anyhow::anyhow!(
            "Cycle detected: URI '{}' already visited",
            uri
        ));
    }
    if depth >= MAX_DEPTH {
        return Err(anyhow::anyhow!(
            "Maximum traversal depth ({}) exceeded at URI '{}'",
            MAX_DEPTH,
            uri
        ));
    }
    // Mark current URI as visited *before* the network call
    visited_uris.insert(uri.to_string());

    let manifest_text = fetch_manifest_text(uri)
        .await
        .with_context(|| format!("Failed to fetch manifest text from URI '{}'", uri))?;


    let statement_payload = verify_signature_with_pae(&manifest_text, expected_identity)
        .with_context(|| {
            format!(
                "Signature/identity verification failed for URI '{}' with expected identity '{}'",
                uri, expected_identity
            )
        })?;

    let statement: InTotoStatement = serde_json::from_slice(&statement_payload) // Using from_slice since we already have bytes
       .with_context(|| format!("Failed to parse InTotoStatement JSON from URI '{}'", uri))?;

    let predicate = models::chainsights::parse_predicate(&statement).with_context(|| {
        format!(
            "Failed to parse ChainsightsPredicate from statement at URI '{}'",
            uri
        )
    })?;

    Ok(predicate)
}