package certcreator

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestCreateCert(t *testing.T) {
	var outputpath, caKeyPath, caCertPath string
	if isWindows() {
		outputpath = ".\\keys\\server.key"
		caKeyPath = ".\\keys\\ca.key.pem"
		caCertPath = ".\\keys\\ca.cert.pem"
	} else {
		outputpath = "./keys/server.key"
		caKeyPath = "./keys/ca.key.pem"
		caCertPath = "./keys/ca.cert.pem"
	}
	err := CreateCert("server.crt", outputpath, caKeyPath, caCertPath, "")
	if err != nil {
		log.Fatal("failed to create/sign server.crt", err)
	}
}

func TestEncryptedCert(t *testing.T) {
	var outputpath, caKeyPath, caCertPath string
	if isWindows() {
		outputpath = ".\\keys\\encrypted_keys\\server.key"
		caKeyPath = ".\\keys\\encrypted_keys\\ca.key.pem"
		caCertPath = ".\\keys\\encrypted_keys\\ca.cert.pem"
	} else {
		outputpath = "./keys/encrypted_keys/server.key"
		caKeyPath = "./keys/encrypted_keys/ca.key.pem"
		caCertPath = "./keys/encrypted_keys/ca.cert.pem"
	}
	err := CreateCert("server.crt", outputpath, caKeyPath, caCertPath, "N0y#Xr7mwy")
	if err != nil {
		log.Fatal("failed to create/sign server.crt", err)
	}
}
