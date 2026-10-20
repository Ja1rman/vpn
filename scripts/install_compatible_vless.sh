#!/usr/bin/env bash
# Install only the new compatible listener; never restart x-ui or the egress pool.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/compatible_vless.py" install "$@"
