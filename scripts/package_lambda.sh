#!/usr/bin/env bash
set -euo pipefail
rm -rf dist
mkdir -p dist/package
python -m pip install -r requirements.txt -t dist/package
cp -r src dist/package/
cp -r risk_policy.py dist/package/
(cd dist/package && zip -qr ../lambda.zip .)
echo "Created dist/lambda.zip"
# Build by Imran Haider
