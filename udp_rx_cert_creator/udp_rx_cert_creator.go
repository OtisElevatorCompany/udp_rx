package main

import (
	"flag"
	"log"

	certcreator "../cert_creator"
)

func main() {
	// ca inputs
	caKeyPathFlag := flag.String("keypath", "./ca.key", "path to the keyfile")
	caKeyPasswordFlag := flag.String("keypass", "", "password for private key if encrypted")
	caCertPathFlag := flag.String("certpath", "./ca.crt", "path to the certfile")
	// device key output
	deviceKeyFlag := flag.String("devkey", "/etc/udp_rx/udp_rx.key", "The output path for the udp_rx device key")
	deviceCertFlag := flag.String("devcert", "/etc/udp_rx/udp_rx.crt", "The oputput path for the udp_rx device cert")
	// parse args
	flag.Parse()
	// create the certs
	err := certcreator.CreateCert(*deviceCertFlag, *deviceKeyFlag, *caKeyPathFlag, *caCertPathFlag, *caKeyPasswordFlag)
	if err != nil {
		log.Panic("Error create a key and certificate. Error: ", err.Error())
	}
}
