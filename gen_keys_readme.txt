============ FINAL NEW FLOW ============
-you NEED keys/ca.cert.pem and keys/ca.key.pem
    -this is the certificate authority
    -generated with:
        openssl genrsa -out private/ca.key.pem 4096
        openssl req -key ca.key.pem -new -x509 -days 36500 -sha256 -extensions v3_ca -out ca.cert.pem
            -US, CT, Farmington, Otis Elevator, Compass COE, blank, blank
    -creates a root cert good for 100 years

-at startup a check is made for keys/server.key
    -if one doesn't exist, a new one is created with the following parameters (in openssl format)
        openssl ecparam -genkey -name prime256v1 -out server.key

-a certificate is generated at runtime and signed with the root CA (ca.cert.pem)
    -generates server.crt

-the root cert (ca.cert.pem) is added to the trusted CA's at runtime

-the newly signed server.crt is setup for client auth and server auth
    -it is the cert delivered with new outbound connections (client auth)
    -it is also the cert delivered to new clients (server auth)
