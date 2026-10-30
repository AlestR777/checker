#!/bin/sh
cd "$(dirname "$0")" || exit 1
set -eu
if [ -x .venv/bin/python ]; then
    TW_PYTHON=.venv/bin/python
else
    TW_PYTHON=python3
fi
"$TW_PYTHON" -m threatwatch init
exec "$TW_PYTHON" -m threatwatch serve
