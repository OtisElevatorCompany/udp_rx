// Copyright 2018 Otis Elevator Company. All rights reserved.
// Use of this source code is govered by the MIT license which
// can be found in the LICENSE file.

// Author: Jeremy Mill: jeremy.mill@otis.com

// Otis udp_rx software has been designed to utilize information
// security technology described in the Category 5 – Part 2 of the
// Commerce Control List, within Part 774 of the Export Administration
// Regulations (“EAR”)(15 CFR 774).  However, the Otis udp_rx software
// has been made publicly available in accordance with Part 742.15(b)
// of the EAR and is therefore not subject to U.S. export regulations.
// Before downloading this software, be aware that the country in which
// you are located may have restrictions related to the import, download,
// possession, use and/or reexport of encryption items.  It is your
// responsibility to comply with any applicable laws and regulations
// pertaining the import, download, possession, use and/or reexport of
// encryption items.

package certcreator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// CreateCert waits for a time > year 1970, then creates a certificate for the current ip address valid for 10 years
func CreateCert(outpath, keypath, caKeyPath, caCertPath, keypassword string) error {
	blockUntilTimeSync()
	//check if the keyfile already exists, and if it doesn't, create it
	checkOrCreatePrivateKey(keypath)

	//get IP addresses
	ips, err := GetIps()
	if err != nil {
		log.Fatal("error getting ips", err)
	}

	//load the certificate authority certificate
	caCert, err := loadCaCert(caCertPath)
	if err != nil {
		log.Fatal("Couldn't load/parse CA cert", err)
	}

	//load the certificate authority private key
	caKey := loadCaPrivateKey(caKeyPath, keypassword)

	//create the new certificate which will be signed by the CA
	newCert := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"Otis Elevator"},
			Country:       []string{"US"},
			Province:      []string{"Connecticut"},
			Locality:      []string{"Farmington"},
			StreetAddress: []string{"5 Farm Springs"},
			PostalCode:    []string{"06032"},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           ips,
	}

	//read the key
	keyPEMBlock, err := ioutil.ReadFile(keypath)
	if err != nil {
		log.Fatal("Couldn't read key file", err)
	}

	//read public key from keyPEMBlock to pubkey
	var skippedBlockTypes []string
	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				panic("tls: failed to find any PEM data in key input")
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				panic("tls: found a certificate rather than a key in the PEM for the private key")
			}
			panic(fmt.Sprintf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	_, pubkey, err := parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatal("Couldn't get key info from keyfile", err)
	}

	//sign the new cert with the CA and set the pubkey from the key read above
	//write those bytes to newCertB, and then those bytes to a file @outpath by PEM encoding
	var newCertB []byte
	newCertB, err = x509.CreateCertificate(
		rand.Reader, //rand reader
		newCert,     //cert we're going to sign
		caCert,      //the CA's cert
		pubkey,      //the pubkey of the new cert
		caKey)       //the priv key of the CA
	if err != nil {
		log.Fatal("Couldn't create certificate file", err)
	}
	certOut, err := os.Create(outpath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: newCertB})
	certOut.Close()
	return nil
}

// CreateCertInMemory creates a new client keypair in memory without writing to disk.
// It returns (in pem format) newCert, newKey, error
func CreateCertInMemory(caKeyPath, caCertPath, caKeyPassword string,
	ips []net.IP, hostnames []string) ([]byte, []byte, error) {
	//build new private key
	newPrivKey := createPrivateKeyInMemory()
	//load the certificate authority certificate
	caCert, err := loadCaCert(caCertPath)
	if err != nil {
		log.Fatal("Couldn't load/parse CA cert", err)
	}
	//load the certificate authority private key
	caKey := loadCaPrivateKey(caKeyPath, caKeyPassword)
	//create the new certificate which will be signed by the CA
	newCert := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"Otis Elevator"},
			Country:       []string{"US"},
			Province:      []string{"Connecticut"},
			Locality:      []string{"Farmington"},
			StreetAddress: []string{"5 Farm Springs"},
			PostalCode:    []string{"06032"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              hostnames,
	}
	//get the public key from the private key
	_, pubkey, err := parsePrivateKey(newPrivKey)
	if err != nil {
		log.Fatal("Couldn't get key info from keyfile", err)
	}
	//create a new certificate
	var newCertB []byte
	newCertB, err = x509.CreateCertificate(
		rand.Reader, //rand reader
		newCert,     //cert we're going to sign
		caCert,      //the CA's cert
		pubkey,      //the pubkey of the new cert
		caKey)       //the priv key of the CA
	if err != nil {
		log.Fatal("Couldn't create certificate file", err)
	}
	//pem encode the key and the newly created certificate
	newCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCertB})
	newKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newPrivKey})
	return newCertPem, newKeyPem, nil
}

func loadCaPrivateKey(caKeyPath, keypassword string) crypto.PrivateKey {
	//load the certificate authority private key
	var caKey crypto.PrivateKey
	var err error
	if keypassword == "" {
		caKey, err = loadCaKey(caKeyPath)
		if err != nil {
			log.Fatal("Couldn't load/parse CA key", err)
		}
	} else {
		caKey, err = loadEncryptedCaKey(caKeyPath, keypassword)
		if err != nil {
			log.Fatal("Couldn't load/parse CA key", err)
		}
	}
	return caKey
}

//load the CA certificate from a path and return an x509 cert
func loadCaCert(caCertPath string) (*x509.Certificate, error) {
	caCertBytes, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	caCertBlock, _ := pem.Decode(caCertBytes)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return caCert, nil
}

//load the CA key from a path and return the private key
func loadCaKey(caKeyPath string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		log.Fatal("Couldn't read CA key file", err)
	}
	caKeyBlock, _ := pem.Decode(keyBytes)
	caKey, _, err := parsePrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return caKey, nil
}

func loadEncryptedCaKey(caKeyPath string, password string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		log.Fatal("Couldn't read encrypted CA key file", err)
	}
	caKeyBlock, _ := pem.Decode(keyBytes)
	isEnc := x509.IsEncryptedPEMBlock(caKeyBlock)
	if !isEnc {
		log.Panic("Tried to decrypt unencrypted pem block")
	}
	decryptedKeyBytes, err := x509.DecryptPEMBlock(caKeyBlock, []byte(password))
	if err != nil {
		log.Panic("Couldn't decrypt CA Private Key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(decryptedKeyBytes)
	if err != nil {
		log.Panic("Couldn't parse key")
	}
	_ = priv
	caKey, _, err := parsePrivateKey(decryptedKeyBytes)
	if err != nil {
		return nil, err
	}
	return caKey, nil
}

//if a private key exists at this location, do nothing. Otherwise, create a new keypair
//with p256
func checkOrCreatePrivateKey(keypath string) {
	if _, err := os.Stat(keypath); os.IsNotExist(err) {
		// path/to/whatever does not exist
		keyOut, err := os.Create(keypath)
		if err != nil {
			log.Fatal("no key detected and couldn't write one", err)
		}
		marshaledKey := createPrivateKeyInMemory()
		pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledKey})
		keyOut.Close()
		log.Info("Created new private key")
	} else {
		log.Debug("Private key already exists")
	}
}

// createPrivateKeyInMemory creates a private key and returns []bytes in DER format if the key doesn't exist.
// if the key does exist, returns the DER encoding of it
func createPrivateKeyInMemory() []byte {
	//if the file doesn't exist:
	log.Debug("Creating new private key")
	genPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Couldn't generate private key", err)
	}
	marshaledKey, err := x509.MarshalECPrivateKey(genPrivKey)
	if err != nil {
		log.Fatal("Couldn't marshal private key", err)
	}
	return marshaledKey
}

//this function blocks until NTP syncs. We don't want to create a 10 year cert from
//1970 then update the time and have an expired cert
func blockUntilTimeSync() {
	log.Debug("Starting time sync wait")
	for {
		ctime := time.Now()
		if ctime.Year() > 1970 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Time Sync finished, unblocking")
}

// GetIps gets all of the IP addresses assigned to this device.
func GetIps() ([]net.IP, error) {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// handle err
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Warning("Error getting addresses", err)
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("No IP Addresses")
	}
	return ips, nil
}

//Parses a private key from a []byte and returns the keypair
func parsePrivateKey(der []byte) (crypto.PrivateKey, crypto.PublicKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, &key.PublicKey, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, &key.PublicKey, nil
		case *ecdsa.PrivateKey:
			return key, &key.PublicKey, nil
		default:
			return nil, nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, &key.PublicKey, nil
	}

	return nil, nil, errors.New("tls: failed to parse private key")
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
