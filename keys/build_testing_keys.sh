openssl genrsa -out ca.key.pem 4096
openssl req -key ca.key.pem -new -x509 -days 36500 -sha256 -extensions v3_ca -out ca.cert.pem
go run build_testing_keys.go