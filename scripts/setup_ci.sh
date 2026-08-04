#!/bin/bash

# CI Setup script for SupportProxy
# Sets up the CI environment for testing

set -e  # Exit on any error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Ensure we're running from repository root
cd "$(dirname "$0")/.."

echo "=== Setting up CI environment for SupportProxy tests ==="

# ffmpeg is a real test dependency, not a convenience. RTSP and RTMP
# ingest hand the stream to an ffmpeg child, and the video tests skip
# themselves without it -- so leaving it out means the whole ingest,
# recording and viewer suite silently does not run in CI.
echo "Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y \
    g++ \
    make \
    libtdb-dev \
    libssl-dev \
    libcrypto++-dev \
    pkg-config \
    python3-tdb \
    python3-pip \
    python3-venv \
    libtdb1 \
    ffmpeg

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment with system site packages..."
    python3 -m venv --system-site-packages venv
fi
echo "Setting up Python virtual environment..."
source venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip
pip install pytest pytest-xdist pymavlink wsproto Flask Flask-WTF

echo "Verifying tdb module accessibility..."
python3 -c "import tdb; print('tdb module is available')"

echo "CI setup completed successfully"
