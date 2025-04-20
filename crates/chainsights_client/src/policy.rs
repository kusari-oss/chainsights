// SPDX-License-Identifier: Apache-2.0

use crate::models::{chainsights::ChainsightsCatalogPredicate, statement::InTotoStatement};
use anyhow::Result;

// TODO: Implement actual policy checking
fn _check_policy(statement: &InTotoStatement) -> Result<Option<ChainsightsCatalogPredicate>> {
    println!("Checking policy...");
    const CHAINSIGHTS_PREDICATE_TYPE: &str = "https://chainsights.rest/catalog/v1";
    if statement.predicate_type == "text/json" {
        println!("  Outer type text/json, checking inner");
        match serde_json::from_value::<ChainsightsCatalogPredicate>(statement.predicate.clone()) {
            Ok(inner_predicate) => {
                let inner_type = statement
                    .predicate
                    .get("predicateType")
                    .and_then(|v| v.as_str());
                if inner_type == Some(CHAINSIGHTS_PREDICATE_TYPE) {
                    println!("  Inner type matches: {}", CHAINSIGHTS_PREDICATE_TYPE);
                    println!("  ✅ Policy checks passed (Placeholder).");
                    return Ok(Some(inner_predicate));
                } else {
                    println!(
                        "  WARN: Inner type mismatch: expected '{}', found '{}'",
                        CHAINSIGHTS_PREDICATE_TYPE,
                        inner_type.unwrap_or("N/A")
                    );
                    return Ok(None);
                }
            }
            Err(e) => {
                println!("  WARN: Cannot parse inner predicate: {}", e);
                return Ok(None);
            }
        }
    } else if statement.predicate_type == CHAINSIGHTS_PREDICATE_TYPE {
        println!("  Predicate type matches: {}", CHAINSIGHTS_PREDICATE_TYPE);
        match serde_json::from_value::<ChainsightsCatalogPredicate>(statement.predicate.clone()) {
            Ok(predicate) => {
                println!("  ✅ Policy checks passed (Placeholder).");
                Ok(Some(predicate))
            }
            Err(e) => {
                println!("  WARN: Cannot parse predicate: {}", e);
                Ok(None)
            }
        }
    } else {
        println!(
            "  WARN: Unexpected predicate type: {}",
            statement.predicate_type
        );
        Ok(None)
    }
}
