#!/usr/bin/env bash
# Download Lab Recon (if needed) and install its Python dependencies.
# This script never asks for, writes, or stores an API key.

set -euo pipefail

REPO_URL="https://github.com/ji9-alt/lab-recon.git"
DIR_NAME="lab-recon"

if [[ -f app.py && -f requirements.txt ]]; then
  ROOT="$(pwd)"
elif [[ -n "${BASH_SOURCE[0]:-}" && -f "$(dirname "${BASH_SOURCE[0]}")/app.py" ]]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  git clone "$REPO_URL" "$DIR_NAME"
  ROOT="$(pwd)/$DIR_NAME"
fi

cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo
echo "Lab Recon is installed in $ROOT"
echo "Start it with:"
echo "  cd $ROOT"
echo "  source .venv/bin/activate"
echo "  python app.py"
echo
echo "For the CoyoteGPT note, export COYOTE_API_KEY in that same terminal."
echo "Do not save the key in this folder."
echo
echo "The class link is created with: python app.py --share"
