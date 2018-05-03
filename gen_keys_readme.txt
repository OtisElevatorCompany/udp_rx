The keys in this directory were generated with the following command:

openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650

This generates a key using NIST-P256 ECC key and a cert good for 10 years