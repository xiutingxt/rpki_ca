#!/bin/sh
# Create an experiment TLS root and a separate localhost server certificate.
set -eu
cd "$(dirname "$0")"
mkdir -p tls
for file in ca.key ca.crt server.key server.crt; do
    if [ -e "tls/$file" ]; then
        echo "Refusing to overwrite tls/$file" >&2
        exit 1
    fi
done
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
    -keyout tls/ca.key -out tls/ca.crt -subj '/CN=RPKI repository experiment root' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -keyout tls/server.key -out tls/server.csr -subj '/CN=localhost'
cat > tls/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in tls/server.csr -CA tls/ca.crt -CAkey tls/ca.key \
    -CAcreateserial -out tls/server.crt -days 365 -sha256 -extfile tls/server.ext
# NGINX worker UID must be able to traverse/read the public RRDP directory;
# its master runs as root and can read the private TLS key.
chmod 644 tls/ca.crt tls/server.crt
