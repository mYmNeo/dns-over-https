#!/bin/bash
# Certificate generation script for DNS-over-HTTPS server
# This script generates a complete TLS setup with client authentication

set -e

echo "Generating TLS certificates for DNS-over-HTTPS server..."

# Generate CA private key
echo "1. Generating CA private key..."
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
echo "2. Generating CA certificate..."
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=CA/L=San Francisco/O=DNS-over-HTTPS/OU=IT Department/CN=doh-ca"

# Generate server private key
echo "3. Generating server private key..."
openssl genrsa -out server-key.pem 4096

# Generate server certificate request
echo "4. Generating server certificate request..."
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=CA/L=San Francisco/O=DNS-over-HTTPS/OU=IT Department/CN=doh-server"

# Sign server certificate with CA
echo "5. Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days 365

# Generate client private key
echo "6. Generating client private key..."
openssl genrsa -out client-key.pem 4096

# Generate client certificate request
echo "7. Generating client certificate request..."
openssl req -new -key client-key.pem -out client.csr \
    -subj "/C=US/ST=CA/L=San Francisco/O=DNS-over-HTTPS/OU=IT Department/CN=doh-client"

# Sign client certificate with CA
echo "8. Signing client certificate with CA..."
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out client-cert.pem -days 365

# Create PKCS#12 bundle for client (for easy import into browsers/clients)
echo "9. Creating client PKCS#12 bundle..."
openssl pkcs12 -export -out client.p12 -inkey client-key.pem -in client-cert.pem \
    -certfile ca-cert.pem -passout pass:dohclient

# Set proper permissions
chmod 600 *.pem *.p12
chmod 644 *.csr

echo ""
echo "Certificate generation completed!"
echo ""
echo "Generated files:"
echo "  - ca-cert.pem     : CA certificate (for client auth)"
echo "  - ca-key.pem      : CA private key (keep secure!)"
echo "  - server-cert.pem : Server certificate"
echo "  - server-key.pem  : Server private key"
echo "  - client-cert.pem : Client certificate"
echo "  - client-key.pem  : Client private key"
echo "  - client.p12      : Client certificate bundle (password: dohclient)"
echo ""
echo "To use these certificates:"
echo "  1. Update doh-server.conf with the certificate paths"
echo "  2. Enable tls_client_auth = true in the config"
echo "  3. Clients must present a valid certificate signed by the CA"
echo ""
echo "To test the server:"
echo "  curl -k --cert client-cert.pem --key client-key.pem https://localhost:8053/dns-query?name=example.com&type=A"