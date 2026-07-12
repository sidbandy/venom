#!/bin/sh
# Build a throwaway git repo whose history contains a secret that was "removed"
# in a later commit — but remains permanently recoverable. Demonstrates Venom's
# full-history secret scanning (SPEC.md §4 M4, §13).
#
# The key is assembled from parts so THIS script contains no literal secret.
set -e

DIR=$(mktemp -d)
cd "$DIR"
git init -q
git config user.email demo@venom.dev
git config user.name "Venom Demo"
git config commit.gpgsign false

KEY="AKIA""ROSFODNN7DEMOKEY"
printf 'const awsKey = "%s";\n' "$KEY" >config.js
git add config.js
git commit -qm "Add service config with credentials"

# "Fix" the leak by deleting the file — but git never forgets.
git rm -q config.js
git commit -qm "Remove hardcoded credentials"

echo "Planted-secrets demo repo created at:"
echo "  $DIR"
echo
echo "Now run:"
echo "  venom secrets \"$DIR\""
echo
echo "Venom recovers the AWS key from the deleted commit in history."
