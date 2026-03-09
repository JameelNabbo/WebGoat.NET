#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building Java SAST Scanner ==="

# Clean previous builds
echo "Cleaning..."
rm -rf target/

# Build with Maven
echo "Building with Maven (this may take a minute on first run)..."
mvn clean package -q -DskipTests

# Check if build succeeded
if [ -f "target/java-sast-scanner-1.0.0.jar" ]; then
    echo ""
    echo "=== Build successful! ==="
    echo "JAR: target/java-sast-scanner-1.0.0.jar"
    echo "Size: $(du -h target/java-sast-scanner-1.0.0.jar | cut -f1)"
    echo ""
    echo "Run with:"
    echo "  java -jar target/java-sast-scanner-1.0.0.jar [port]"
    echo "  Default port: 9004"
    echo ""
else
    echo "Build failed!"
    exit 1
fi
