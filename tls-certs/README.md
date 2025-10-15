# TLS Certificates for DNS-over-HTTPS Server

This directory contains TLS certificates for enabling HTTPS with client authentication on the DNS-over-HTTPS server.

## Files Generated

- `ca-cert.pem` - Root CA certificate (used for client authentication)
- `ca-key.pem` - Root CA private key (keep secure!)
- `server-cert.pem` - Server certificate signed by the CA
- `server-key.pem` - Server private key
- `client-cert.pem` - Client certificate signed by the CA
- `client-key.pem` - Client private key
- `client.p12` - Client certificate bundle (password: `dohclient`)
- `*.csr` - Certificate signing requests (can be deleted)

## Configuration

The server configuration has been updated to use these certificates:

```toml
# TLS settings
cert = "tls-certs/server-cert.pem"
key = "tls-certs/server-key.pem"

# Client authentication
tls_client_auth = true
tls_client_auth_ca = "tls-certs/ca-cert.pem"
```

## Usage

### Starting the Server

```bash
cd doh-server
./doh-server -conf doh-server.conf
```

### Testing with curl

```bash
# Test with client certificate
curl -k --cert tls-certs/client-cert.pem --key tls-certs/client-key.pem \
    "https://localhost:8053/dns-query?name=example.com&type=A" \
    -H "Accept: application/json"

# Test without client certificate (should fail)
curl -k "https://localhost:8053/dns-query?name=example.com&type=A"
```

### Using the Test Script

```bash
./tls-certs/test-server.sh
```

## Client Certificate Installation

### For curl/command line tools:
Use the PEM files directly:
- Certificate: `client-cert.pem`
- Private key: `client-key.pem`

### For browsers:
Import the PKCS#12 file:
- File: `client.p12`
- Password: `dohclient`

### For other applications:
Most applications can use either the PEM files or the PKCS#12 bundle.

## Security Notes

1. **Keep private keys secure**: Never share `*-key.pem` files
2. **CA key protection**: The `ca-key.pem` should be stored securely and backed up
3. **Certificate expiration**: These certificates expire in 365 days
4. **Regeneration**: Use `./generate-certs.sh` to regenerate all certificates

## Regenerating Certificates

To regenerate all certificates:

```bash
rm -f *.pem *.csr *.p12 *.srl
./generate-certs.sh
```

## Troubleshooting

### Server won't start
- Check that certificate files exist and are readable
- Verify the paths in `doh-server.conf` are correct
- Check file permissions (certificates should be readable, keys should be 600)

### Client authentication fails
- Ensure the client certificate is signed by the same CA
- Check that `tls_client_auth = true` in the server config
- Verify the client is presenting the certificate correctly

### Certificate verification errors
- For testing, use `-k` flag with curl to skip hostname verification
- In production, ensure server certificate CN matches the hostname