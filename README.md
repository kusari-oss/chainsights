# Chainsights

Chainsights is a proof-of-concept protocol and client tool for software supply chain transparency. It enables organizations to publish and verify metadata about their software components, releases, and associated attestations in a hierarchical, discoverable format.

**NOTE:** The project is VERY early. It is a working PoC, but there's a lot more to be done before it would be safe and secure for broad use. Both the tool and protocol need a lot more work. We welcome issues, conversations, and collaboration. We plan to also collaborate with existing groups doing similar work like OWASP's Transparency Exchange API. This project is not intended to replace any existing supply chain security focused APIs and architectures but complement them.

This project is currently developed and maintained by Kusari.

## Overview

The Chainsights protocol creates a verifiable, linked graph of software metadata starting from a domain's DNS records:

- Catalog: The root level manifest that lists components and sub-catalogs
- Component: Represents a software unit with links to repositories and releases
- Release: Contains information about specific versions including links to artifacts and metadata

All manifests are signed in-toto statements that can be cryptographically verified.

## Installation

```bash
# Clone the repository
git clone https://github.com/kusari-oss/chainsights.git
cd chainsights

# Build the client
cargo build --release

# The binary will be available at target/release/chainsights_client
```

## Usage

### Querying by Domain

To discover and traverse all components and releases associated with a domain:

```bash
chainsights_client domain --domain example.com
```

This will:

1. Query the DNS TXT record for _chainsights.example.com
2. Fetch the root catalog from the URI found in the TXT record
3. Recursively traverse all components and their releases
4. Output the aggregated data as JSON

### Querying by PURL

To query for a specific component or release:

```bash
# Query for a component
chainsights_client purl --purl pkg:chainsights/example.com/my-component

# Query for a specific release
chainsights_client purl --purl pkg:chainsights/example.com/my-component@1.0.0

# Get all releases for a component
chainsights_client purl --purl pkg:chainsights/example.com/my-component --all-releases

# Fetch and display SBOM data for a release
chainsights_client purl --purl pkg:chainsights/example.com/my-component@1.0.0 --fetch-sbom application/spdx+json
```

### DNS TXT Record Format

To enable Chainsights discovery for your domain, add a TXT record for _chainsights.yourdomain.com with the following format:
`uri=https://example.com/path/to/chainsights.jsonl identity=your-email@example.com`
Example:
`_chainsights.example.com. 300 IN TXT "uri=https://raw.githubusercontent.com/example/chainsights/main/chainsights.jsonl identity=security@example.com"`
This record should contain:

- uri: A link to your root catalog manifest
- identity: The expected signer identity for signature verification

## How It Works

- Discovery: The client queries DNS to find the root catalog URI
- Verification: All manifests are verified using Sigstore signatures
- Traversal: The client recursively follows links between manifests
- Aggregation: Data is collected into a comprehensive view of your supply chain

## Manifest Structure Examples

### Catalog Example

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "uri": "pkg:chainsights/example.com",
      "digest": {
        "sha256": "823dba926f0df95090bff6623eee44edc6074608971bd8acec37839e2f7ef1c3"
      }
    }
  ],
  "predicateType": "https://chainsights.rest/catalog/v1",
  "predicate": {
    "timestamp": "2025-04-20T05:05:22Z",
    "components": [
      {
        "name": "Example Component",
        "description": "A sample component.",
        "componentPurl": "pkg:generic/example.com/my-component",
        "componentAttestationLink": {
            "uri": "https://example.com/components/my-component.jsonl",
            "expectedSignerIdentity": "security@example.com"
        }
      }
    ]
  }
}
```

### Component Example

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "uri": "pkg:chainsights/example.com/my-component",
      "digest": {
        "sha256": "440a0b06af70f8c6caf028946961401cea8881e603eacc4ac31b808ec312e30f"
      }
    }
  ],
  "predicateType": "https://chainsights.rest/component/v1",
  "predicate": {
    "timestamp": "2025-04-20T05:05:22Z",
    "purl": "pkg:generic/example.com/my-component",
    "name": "Example Component",
    "repositories": [
      {
        "repoType": "git",
        "uri": "https://github.com/example/my-component"
      }
    ],
    "releaseAttestations": [
      {
        "uri": "https://example.com/components/my-component/1.0.0.jsonl",
        "expectedSignerIdentity": "security@example.com"
      }
    ],
    "metadataLinks": [
      {
        "uri": "https://example.com/components/my-component/baseline.jsonl",
        "mediaType": "application/in-toto+json"
      }
    ]
  }
}
```

### Release Example

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "uri": "pkg:chainsights/example.com/my-component@1.0.0",
      "digest": {
        "sha256": "c299fcd89e35d587ad3590b73947ec7046365229e689878b7f9e96497549e7f9"
      }
    }
  ],
  "predicateType": "https://chainsights.rest/release/v1",
  "predicate": {
    "timestamp": "2025-04-20T05:05:22Z",
    "purl": "pkg:generic/example.com/my-component@1.0.0",
    "name": "Example Component 1.0.0 Release",
    "releaseDate": "2025-04-20T05:05:22Z",
    "metadataLinks": [
      {
        "uri": "https://example.com/components/my-component/1.0.0/sbom.spdx.json",
        "mediaType": "application/spdx+json"
      }
    ]
  }
}
```

## Security Features

**NOTE**: Some of these aren't implemented very well yet.

- All manifests are verified using Sigstore signatures
- Hash verification for non-signed artifacts
- Expected signer identity checking
- Cycle detection to prevent infinite traversal
- Depth limiting to prevent excessive resource usage

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Contributing

Chainsights welcomes contributions.

The project just started, so there is currently no contributing guide, but expect this to change shortly.
