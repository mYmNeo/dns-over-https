#!/bin/bash
# Test script for DNS-over-HTTPS server with TLS client authentication

set -e

echo "Testing DNS-over-HTTPS server with TLS client authentication..."
echo ""

# Check if server is running
if ! pgrep -f "doh-server" > /dev/null; then
    echo "Error: doh-server is not running. Please start it first with:"
    echo "  ./doh-server/doh-server -conf doh-server/doh-server.conf"
    exit 1
fi

echo "Server is running. Testing with client certificate authentication..."
echo ""

# Test DNS query with client certificate
echo "Testing DNS query for example.com (A record):"
curl -k --cert client-cert.pem --key client-key.pem \
    "https://localhost:8053/dns-query?name=example.com&type=A" \
    -H "Accept: application/json" | jq .

echo ""
echo "Testing DNS query for google.com (A record):"
curl -k --cert client-cert.pem --key client-key.pem \
    "https://localhost:8053/dns-query?name=google.com&type=A" \
    -H "Accept: application/json" | jq .

echo ""
echo "Testing without client certificate (should fail):"
curl -k "https://localhost:8053/dns-query?name=example.com&type=A" \
    -H "Accept: application/json" || echo "Expected failure - no client certificate provided"

echo ""
echo "Test completed!"