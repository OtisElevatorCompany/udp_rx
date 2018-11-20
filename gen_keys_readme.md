# Building a CA
Otis provides a development CA for use by developers who are seeking to use this utility to interact with Otis devices. If you are working with Otis Elevator, please contact your representative to get a copy of the development CA. 

You can also generate a CA with the following commands:

```shell
openssl genrsa -out ca.key 4096
openssl req -key ca.key -new -x509 -days 36500 -sha256 -extensions v3_ca -out ca.crt
```

# Building a device certificate
Either use the pre-built binary that came with a release, or run `go build` in the `udp_rx_cert_creator` folder to build the udp_rx_cert_creator. 

To build a device certificate for IP address `192.168.1.250` and `192.168.1.251`, make sure that ca.crt and ca.key are in the same folder as the udp_rx_cert_creator (or use the `-keypath` and `-certpath` flags) and run the following command:

```shell
udp_rx_cert_creator -ips="192.168.1.250,192.168.1.250"
```

This generates `udp_rx.key` and `udp_rx.crt` which is the device keypair for use in udp_rx.

## udp_rx_cert_creator options
```shell
-certpath string
    path to the certfile (default "./ca.crt")
-devcert string
    The output path for the udp_rx device cert (default "udp_rx.crt")
-devkey string
    The output path for the udp_rx device key (default "udp_rx.key")
-ips string
    A comma separated string of IP addresses. If not set, it will use this
    system's IP addresses
-keypass string
    password for private key if encrypted
-keypath string
    path to the keyfile (default "./ca.key")
```
