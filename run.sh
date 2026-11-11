#!/bin/sh
# Start the ODC explorer on Linux (any arguments are passed through, e.g. --open).
cd "$(dirname "$0")" || exit 1
exec python3 -m odc_explorer "$@"
