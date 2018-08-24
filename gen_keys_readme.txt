============ Keys ============
-you need (names and paths are defaults) ./keys/server.crt and ./keys/server.key
-you may also have (names and paths are defaults) ./keys/ca.cert.pem
    -ca.cert.pem is the CA certificate. It will be appended to the root certificate 
    store for this process only (if included)
    -can be generated with:
        openssl genrsa -out private/ca.key.pem 4096
        openssl req -key ca.key.pem -new -x509 -days 36500 -sha256 -extensions v3_ca -out ca.cert.pem
        -creates a root cert good for 100 years
    -server.crt and server.key should be a keypair where server.crt is signed by the CA

-server.crt is setup for client auth and server auth
    -it is the cert delivered with new outbound connections (client auth)
    -it is also the cert delivered to new clients (server auth)

-You can use code in the cert_creator package to create and sign a certificate (given a CA) for use with udp_rx

