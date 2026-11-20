#!/bin/bash

# Generate CA private key and certificate
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout websockexca.key -out websockexca.cer \
  -subj "/C=US/ST=Test/L=Test/O=WebSockex/OU=Test/CN=WebSockex Test CA"

# Generate server private key, unless one exists. Keeping the committed key
# avoids pushing a new private key, which GitHub push protection blocks.
[ -f websockex.key ] || openssl genrsa -out websockex.key 4096

# Generate server certificate signing request (CSR)
openssl req -new -key websockex.key -out websockex.csr \
  -subj "/C=US/ST=Test/L=Test/O=WebSockex/OU=Test/CN=localhost"

# Generate server certificate signed by our CA.
# OTP 29 rejects a certificate without subjectAltName.
openssl x509 -req -days 3650 -in websockex.csr \
  -CA websockexca.cer -CAkey websockexca.key \
  -CAcreateserial -out websockex.cer \
  -extfile <(printf "subjectAltName=DNS:localhost")

# Clean up temporary files
rm websockex.csr websockexca.key websockexca.srl

# Set appropriate permissions
chmod 644 websockexca.cer websockex.cer
chmod 600 websockex.key
