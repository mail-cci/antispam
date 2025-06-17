#!/usr/bin/env bash
set -euo pipefail

# Build antispam binary
GOFLAGS="" go build -o antispam ./cmd/antispam

# Start antispam in background and capture PID
./antispam > /tmp/antispam_test.log 2>&1 &
ANTISPAM_PID=$!

# Wait a bit for the server to start
sleep 2

# Send test emails using swaks
if ! command -v swaks >/dev/null 2>&1; then
    echo "swaks is required but not installed" >&2
    kill "$ANTISPAM_PID"
    exit 1
fi

for eml in testdata/*.eml; do
    echo "Sending $eml"
    swaks --server localhost --port 25 --data "$eml" || true
    sleep 1
done

# Allow logs to flush
sleep 2

# Output logs
echo "\n== Milter logs =="
cat /tmp/antispam_test.log

# Shutdown
kill "$ANTISPAM_PID"
wait "$ANTISPAM_PID" 2>/dev/null || true
