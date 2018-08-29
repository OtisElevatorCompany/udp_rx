package main

import (
	certcreator "../cert_creator"
)

func main() {
	certcreator.CreateCert("server.crt", "server.key", "ca.key.pem", "./ca.cert.pem", "")
}
