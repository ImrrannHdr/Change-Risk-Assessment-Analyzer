
#!/usr/bin/env bash
set -euo pipefail

# Find project root.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD_DIR="$PROJECT_ROOT/build"
PACKAGE_DIR="$BUILD_DIR/package"
ZIP_FILE="$BUILD_DIR/lambda.zip"

# This example targets Lambda Python 3.12 on x86_64.
PYTHON_VERSION="3.12"
PLATFORM="manylinux2014_x86_64"

echo "Preparing Lambda deployment package..."

# Clean previous build.
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Install Lambda-compatible dependencies.
"$PROJECT_ROOT/.venv/bin/python" -m pip install \
    --requirement "$PROJECT_ROOT/requirements-lambda.txt" \
    --target "$PACKAGE_DIR" \
    --platform "$PLATFORM" \
    --python-version "$PYTHON_VERSION" \
    --implementation cp \
    --only-binary=:all: \
    --upgrade

# Copy Python source code.
cp -r "$PROJECT_ROOT/src" "$PACKAGE_DIR/"

# Copy YAML configuration.
mkdir -p "$PACKAGE_DIR/config"
cp "$PROJECT_ROOT/config/risk_policy.yaml" \
   "$PACKAGE_DIR/config/risk_policy.yaml"

mkdir -p "$PROJECT_ROOT/dist"
rm -f "$PROJECT_ROOT/dist/lambda.zip"

(
    cd "$PACKAGE_DIR"
    zip -qr "$PROJECT_ROOT/dist/lambda.zip" .
)
# Copy Lambda handler.
# cp "$PROJECT_ROOT/lambda_function.py" "$PACKAGE_DIR/"

# Remove unnecessary Python cache files.
find "$PACKAGE_DIR" -type d -name "__pycache__" \
    -prune -exec rm -rf {} +

find "$PACKAGE_DIR" -type f -name "*.pyc" -delete

# Create the deployment ZIP.
rm -f "$ZIP_FILE"

(
    cd "$PACKAGE_DIR"
    zip -qr "$ZIP_FILE" .
)

echo "Lambda package created: $ZIP_FILE"



# Verify required files exist in the ZIP.
echo "Verifying Lambda deployment package..."

ZIP_CONTENTS="$(unzip -Z -1 "$ZIP_FILE")"

for file in \
    "src/lambda_handler.py" \
    "src/risk_engine.py" \
    "config/risk_policy.yaml" \
    "yaml/__init__.py"
do
    if ! grep -Fxq "$file" <<< "$ZIP_CONTENTS"; then
        echo "ERROR: Missing required file: $file"
        exit 1
    fi

    echo "Verified: $file"
done

echo "Lambda packaging completed successfully."