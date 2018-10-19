openssl genrsa -out ca.key 4096
openssl req -key ca.key -new -x509 -days 36500 -sha256 -extensions v3_ca -out ca.crt