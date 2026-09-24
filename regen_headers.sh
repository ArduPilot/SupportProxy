#!/bin/bash
# Generate headers with the pymavlink revision pinned by our MAVLink submodule.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD/modules/mavlink${PYTHONPATH:+:$PYTHONPATH}"

echo "Generating mavlink2 headers"
rm -rf libraries/mavlink2/generated
python3 modules/mavlink/pymavlink/tools/mavgen.py --no-validate --wire-protocol 2.0 --lang C modules/mavlink/message_definitions/v1.0/all.xml -o libraries/mavlink2/generated

./git-version.sh
