#/usr/bin/env sh

# SPDX-License-Identifier: Apache-2.0

## This script is used to generate example chainsights statements and push them to the chainsights repo under the wtf-chainsights directly.
## Mike uses this to generate example statements for the chainsights repo.

bnd statement --statement example/example_catalog.json >  ../../../wtf-chainsights/chainsights/chainsights.jsonl
bnd statement --statement example/example_component.json > ../../../wtf-chainsights/chainsights/components/wtf-frontend.jsonl
bnd statement --statement example/example_release.json > ../../../wtf-chainsights/chainsights/components/wtf-frontend/0.1.jsonl
bnd statement --statement example/example_baseline.json > ../../../wtf-chainsights/chainsights/components/wtf-frontend/attestations/baseline.jsonl

cd ../../../wtf-chainsights/chainsights
git add .
git commit -m "update chainsights examples"
git push origin main