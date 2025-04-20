// SPDX-License-Identifier: Apache-2.0

mod models;
mod traversal;
mod fetch;
mod attestation;
mod policy;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use fetch::{fetch_and_verify_artifact, fetch_chainsights_info};
use models::aggregation::{AggregatedCatalogData, AggregatedComponentData, AggregatedReleaseData};
use models::chainsights::{ArtifactLink, ChainsightsPredicate};
use packageurl::PackageUrl;
use reqwest;
use traversal::traverse_and_aggregate;
use std::str::FromStr;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query and traverse starting from a domain's root attestation via DNS lookup.
    Domain {
        /// The domain name to query for Chainsights info (e.g., example.com)
        #[arg(long)]
        domain: String,
    },
    /// Query for a specific component/release using a PURL. Traversal starts from the domain's root.
    Purl {
        /// The Package URL (PURL) to query (e.g., pkg:chainsights/example.com/my-component@1.2.0)
        #[arg(long)]
        purl: String,

        /// Fetch all releases for the specified component (ignores version in PURL)
        #[arg(long, default_value_t = false)]
        all_releases: bool,

        /// Fetch and verify SBOM/artifact of the specified media type (e.g., application/spdx+json)
        #[arg(long = "fetch-sbom")]
        fetch_sbom_media_type: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Domain { domain } => {
            handle_commands_domain(domain).await?
        }

        Commands::Purl {
            purl,
            all_releases,
            fetch_sbom_media_type,
        } => {
            handle_commands_purl(purl, all_releases, fetch_sbom_media_type).await?
        }
    }

    Ok(())
}

async fn handle_commands_domain(domain: String) -> Result<()> {
    println!("Querying domain: {}", domain);
    let (root_uri, root_identity) = fetch_chainsights_info(&domain)
        .await
        .with_context(|| format!("Failed to fetch root info for domain '{}'", domain))?;

    println!(
        "Traversing from root URI: {} with expected identity: {}",
        root_uri, root_identity
    );
    let aggregated_data = traverse_and_aggregate(&root_uri, &root_identity)
        .await
        .with_context(|| format!("Traversal failed starting from {}", root_uri))?;

    // Print the full aggregated data as JSON
    let json_output = serde_json::to_string_pretty(&aggregated_data)
        .context("Failed to serialize results to JSON")?;
    println!("{}", json_output);

    Ok(())
}

async fn handle_commands_purl(
    purl: String,
    all_releases: bool,
    fetch_sbom_media_type: Option<String>,
) -> Result<()> {
    let client = reqwest::Client::new();
    println!("Querying PURL: {}", purl);
    let (domain, component_name, purl_version_opt) = parse_chainsights_purl(&purl)
        .with_context(|| format!("Failed to parse PURL '{}'", purl))?;

    println!(
        "Extracted Domain: {}, Component: {}, Version: {:?}",
        domain, component_name, purl_version_opt
    );

    let (root_uri, root_identity) = fetch_chainsights_info(&domain)
        .await
        .with_context(|| format!("Failed to fetch root info for domain '{}'", domain))?;

    println!(
        "Traversing from root URI: {} with expected identity: {}",
        root_uri, root_identity
    );
    let aggregated_data = traverse_and_aggregate(&root_uri, &root_identity)
        .await
        .with_context(|| format!("Traversal failed starting from {}", root_uri))?;

    // --- Filtering Logic ---
    let mut found_releases = Vec::new();
    let mut found_component_data: Option<&AggregatedComponentData> = None;

    if let Some(_catalog) = &aggregated_data.catalog_predicate {
        // Check if catalog was loaded
        for comp_data in &aggregated_data.components {
            if let Some(comp_pred) = &comp_data.component_predicate {
                let name_field = comp_pred.name.clone();
                if name_field == component_name {
                    found_component_data = Some(comp_data);
                    if all_releases {
                        // Keep all releases for this component
                        found_releases.extend(comp_data.releases.iter().cloned()); // Clone data
                    } else {
                        // Filter by PURL version (if provided)
                        if let Some(purl_version) = &purl_version_opt {
                            for rel_data in &comp_data.releases {
                                if let Some(rel_pred) = &rel_data.release_predicate {
                                    // TODO: Adjust field access for version
                                    // Assuming release_predicate has a 'version' field
                                    let purl = PackageUrl::from_str(&rel_pred.purl)
                                        .context("Failed to parse PURL from release predicate")?;
                                    let release_version_field =
                                        purl.version().context("Expected version in purl")?;
                                    if &release_version_field == purl_version {
                                        found_releases.push(rel_data.clone());
                                    }
                                }
                            }
                        } else {
                            // PURL had no version, and --all-releases is false.
                            // Behavior is undefined: error, return latest, return none?
                            // Let's print a warning and return none for now.
                            eprintln!(
                                "Warning: PURL has no version, and --all-releases is not specified. No specific release selected."
                            );
                        }
                    }
                    break; // Found the matching component, stop searching components
                }
            }
        }
    } else if aggregated_data.root_error.is_some() {
        eprintln!(
            "Cannot filter results as the root catalog failed to load: {}",
            aggregated_data.root_error.unwrap()
        );
        return Ok(()); // Exit gracefully after reporting root error
    }

    // --- Printing Filtered Data ---
    if !found_releases.is_empty() {
        println!(
            "\n--- Filtered Releases for Component '{}' ---",
            component_name
        );
        // Decide what to print: just releases or the component + filtered releases
        let output_data = if all_releases || purl_version_opt.is_none() {
            // If all releases or no specific version, maybe print the component context too
            serde_json::json!({
                "component": found_component_data, // Contains original URIs and errors
                "matching_releases": found_releases
            })
        } else {
            // If specific version, just print those releases
            serde_json::json!(found_releases)
        };
        let json_output = serde_json::to_string_pretty(&output_data)
            .context("Failed to serialize filtered results to JSON")?;
        println!("{}", json_output);

        // TODO: Should I just have this handle fetching of any artifacts?
        // --- Conditional SBOM Fetching ---
        if let Some(media_type) = fetch_sbom_media_type {
            println!(
                "\n--- Fetching Artifacts with Media Type '{}' ---",
                media_type
            );
            let mut fetch_futures = Vec::new();

            for release_data in &found_releases {
                for artifact_link in &release_data.metadata_artifacts {
                    if artifact_link.media_type.as_deref() == Some(media_type.as_str()) {
                        println!("Attempting to fetch: {}", artifact_link.uri);
                        // Clone necessary data for the async block
                        let link_clone = artifact_link.clone();
                        let client_clone = client.clone();
                        fetch_futures.push(async move {
                            fetch_and_verify_artifact(&link_clone, &client_clone).await
                        });
                    }
                }
            }

            let fetch_results = futures::future::join_all(fetch_futures).await; // Execute fetches concurrently [10]

            for result in fetch_results {
                match result {
                    Ok(bytes) => {
                        // Attempt to print as UTF-8, fallback for binary
                        match String::from_utf8(bytes.clone()) {
                            Ok(s) => println!("Fetched Artifact Content:\n---\n{}\n---", s),
                            Err(_) => println!(
                                "Fetched Artifact Content: (Binary data, {} bytes)",
                                bytes.len()
                            ),
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to fetch or verify artifact: {}", e);
                        // Error context (URI) is lost here, ideally return (URI, Result) from future
                    }
                }
            }
        }
    } else {
        println!(
            "\nNo matching component or release found for PURL '{}' in the traversed data.",
            purl
        );
        // Optionally print component/release errors from aggregated_data for context
        if let Some(comp_data) = found_component_data {
            if !comp_data.release_errors.is_empty() {
                eprintln!(
                    "Errors encountered while processing releases for component '{}':",
                    component_name
                );
                for (uri, err) in &comp_data.release_errors {
                    eprintln!("  - URI: {}, Error: {}", uri, err);
                }
            }
        } else if !aggregated_data.component_errors.is_empty() {
            eprintln!("Errors encountered while processing components:");
            for (uri, err) in &aggregated_data.component_errors {
                eprintln!("  - URI: {}, Error: {}", uri, err);
            }
        }
    }

    Ok(())
}


/// Parses a PURL string with the custom "chainsights" type.
/// Returns Ok((domain, component_name, version)) on success.
fn parse_chainsights_purl(purl_str: &str) -> Result<(String, String, Option<String>)> {
    // Parse the generic PURL structure [15, 21]
    let purl = PackageUrl::from_str(purl_str)
        .with_context(|| format!("Invalid PURL syntax: '{}'", purl_str))?;

    // 1. Validate the type [22, 23]
    if purl.ty() != "chainsights" {
        // Use ty() method from packageurl 0.4+ [21]
        return Err(anyhow!(
            "PURL type must be 'chainsights', found '{}'",
            purl.ty()
        ));
    }

    // 2. Extract domain from namespace [22, 23, 24]
    // For pkg:chainsights/example.com/component@version, namespace is "example.com"
    let domain = purl.namespace()
       .ok_or_else(|| anyhow!("PURL for 'chainsights' type must contain a domain in the namespace (e.g., pkg:chainsights/example.com/...)"))?
       .to_string();
    // Note: PURL spec allows multiple namespace segments separated by '/'.
    // We assume the *entire* namespace field represents the domain here.
    // If multi-segment namespaces are needed for chainsights, adjust this logic.

    // 3. Extract component name from name [22, 23]
    let component_name = purl.name().to_string();
    if component_name.is_empty() {
        return Err(anyhow!("PURL must contain a component name"));
    }
    // PURL spec allows slashes in name if namespace is empty, but we require a namespace (domain).
    // If component names can contain slashes, ensure `packageurl` crate handles this correctly
    // or perform additional validation/splitting if needed.

    // 4. Extract optional version [21]
    let version = purl.version().map(|v| v.to_string());

    Ok((domain, component_name, version))
}


