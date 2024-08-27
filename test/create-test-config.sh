#!/bin/bash

HERE="$( dirname $0 )"
CERT_DIR="$HERE/certs"
echo $CERT_DIR

CLIENT_KEY="$CERT_DIR/client.key"
CLIENT_CERT="$CERT_DIR/client.crt"
CLIENT_CSR="$CERT_DIR/client.csr"
CLIENT_CONF="$HERE/client.conf"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CERT="$CERT_DIR/server.crt"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CONF="$HERE/server.conf"
CA_CERT="$CERT_DIR/ca.crt"
CA_KEY="$CERT_DIR/ca.key"
DH_PARAMS="$CERT_DIR/dh.pem"
KEY_SIZE=2048

echo Creating Test Configuration...

mkdir -pv "$CERT_DIR"
rm -vf "$CERT_DIR/*{key,crt,csr,pem,srl} $CERT_DIR/*conf"

echo Creating CA key $CA_KEY
openssl genrsa -out $CA_KEY $KEY_SIZE

echo Creating CA cert $CA_CERT
openssl req -x509 -new -nodes -key $CA_KEY -sha256 -days $(( 5 * 365 )) -out $CA_CERT -subj "/CN=Test_CA"

echo Creating server CSR $SERVER_CSR
openssl req -new -nodes -out $SERVER_CSR -newkey rsa:$KEY_SIZE -keyout $SERVER_KEY -subj "/CN=$HOSTNAME"

echo Signing server cert $SERVER_CERT
openssl x509 -req -in $SERVER_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $SERVER_CERT -days 730 -sha256

echo Creating client CSR $CLIENT_CSR
openssl req -new -nodes -out $CLIENT_CSR -newkey rsa:$KEY_SIZE -keyout $CLIENT_KEY -subj "/CN=$HOSTNAME"

echo Signing client cert $CLIENT_CERT
openssl x509 -req -in $CLIENT_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $CLIENT_CERT -days 730 -sha256

echo Creating DH parameters $DH_PARAMS
openssl dhparam -out $DH_PARAMS $KEY_SIZE

echo Creating server configuration $SERVER_CONF
cat <<EOF > $SERVER_CONF
server 192.168.101.0 255.255.255.0
local 0.0.0.0
proto tcp
port 1194
dev-type tun
dev arachne-test
keepalive 10 60
topology subnet
plugin ../rust/target/debug/libopenvpn_arachne_plugin.so
ca $CA_CERT
cert $SERVER_CERT
key $SERVER_KEY
dh $DH_PARAMS
EOF

cat <<EOF > $CLIENT_CONF
client
remote $HOSTNAME 1194 tcp
dev-type tun
dev arachne-client
ca $CA_CERT
key $CLIENT_KEY
cert $CLIENT_CERT
EOF
