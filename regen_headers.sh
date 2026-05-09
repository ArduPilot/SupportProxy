#!/bin/bash
# re-generate mavlink headers, assumes pymavlink is installed

echo "Generating mavlink2 headers"
rm -rf libraries/mavlink2/generated
mavgen.py --no-validate --wire-protocol 2.0 --lang C modules/mavlink/message_definitions/v1.0/all.xml -o libraries/mavlink2/generated

./git-version.sh


