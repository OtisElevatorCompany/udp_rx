package main

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
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	certcreator "github.com/OtisElevatorCompany/udp_rx/cert_creator"
)

func main() {
	// ca inputs
	caKeyPathFlag := flag.String("keypath", "./ca.key", "path to the keyfile")
	caKeyPasswordFlag := flag.String("keypass", "", "password for private key if encrypted")
	caCertPathFlag := flag.String("certpath", "./ca.crt", "path to the certfile")
	// device key output
	deviceKeyFlag := flag.String("devkey", "udp_rx.key", "The output path for the udp_rx device key")
	deviceCertFlag := flag.String("devcert", "udp_rx.crt", "The output path for the udp_rx device cert")
	// specify ip to build for
	ipFlag := flag.String("ips", "", "A comma separated string of IP addresses. If not set, it will use this system's IP addresses")
	// parse args
	flag.Parse()
	// create the certs
	// err := certcreator.CreateCert(*deviceCertFlag, *deviceKeyFlag, *caKeyPathFlag, *caCertPathFlag, *caKeyPasswordFlag)
	if *ipFlag != "" {
		// parse the ip addresses into strings
		ips := strings.Split(*ipFlag, ",")
		caCert, err := ioutil.ReadFile(*caCertPathFlag)
		caKey, err := ioutil.ReadFile(*caKeyPathFlag)
		caCertString := string(caCert)
		caKeyString := string(caKey)
		parsedDkr := deviceKeyRequest{
			Ips:       ips,
			Hostnames: []string{},
			CaCert:    caCertString,
			CaKey:     caKeyString,
			StartTime: time.Now(),
		}
		dkr, err := generateDeviceKeyPair(parsedDkr)
		if err != nil {
			log.Panic("Error create a key and certificate. Error: ", err.Error())
		}
		err = ioutil.WriteFile(*deviceKeyFlag, []byte(dkr.DeviceKey), 0666)
		err = ioutil.WriteFile(*deviceCertFlag, []byte(dkr.DeviceCert), 0666)
		if err != nil {
			log.Panic("Error writing key and cert files. Error: ", err.Error())
		}
	} else {
		err := certcreator.CreateCert(*deviceCertFlag, *deviceKeyFlag, *caKeyPathFlag, *caCertPathFlag, *caKeyPasswordFlag)
		if err != nil {
			log.Panic("Error create a key and certificate. Error: ", err.Error())
		}
	}
}

func generateDeviceKeyPair(dkr deviceKeyRequest) (deviceKeyResponse, error) {
	// parse the IPs
	var ips []net.IP
	for _, ipstring := range dkr.Ips {
		parsedip := net.ParseIP(ipstring)
		if parsedip != nil {
			ips = append(ips, parsedip)
		}
	}
	// create a new private key
	newPrivKey := createPrivateKeyInMemory()
	// load the certificate authority certificate
	caCertBlock, _ := pem.Decode([]byte(dkr.CaCert))
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return deviceKeyResponse{}, err
	}
	// load the certificate authority private key
	caKeyBlock, _ := pem.Decode([]byte(dkr.CaKey))
	caKey, _, err := parsePrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return deviceKeyResponse{}, err
	}
	// get the public key from the private key
	_, pubkey, err := parsePrivateKey(newPrivKey)
	if err != nil {
		return deviceKeyResponse{}, err
	}
	// create the new certificate which will be signed by the CA
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
		NotBefore:             dkr.StartTime.AddDate(0, 0, -1),
		NotAfter:              dkr.StartTime.AddDate(100, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              dkr.Hostnames,
	}
	var newCertB []byte
	newCertB, err = x509.CreateCertificate(
		rand.Reader, // rand reader
		newCert,     // cert we're going to sign
		caCert,      // the CA's cert
		pubkey,      // the pubkey of the new cert
		caKey)       // the priv key of the CA
	if err != nil {
		return deviceKeyResponse{}, err
	}
	newCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCertB})
	newKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newPrivKey})
	return deviceKeyResponse{DeviceCert: string(newCertPem), DeviceKey: string(newKeyPem)}, nil
}
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
func createPrivateKeyInMemory() []byte {
	// if the file doesn't exist:
	//log.Debug("Creating new private key")
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

type deviceKeyRequest struct {
	Ips       []string
	Hostnames []string
	CaCert    string
	CaKey     string
	StartTime time.Time
}

// DeviceKeyResponse is the response to a DeviceKeyRequest
type deviceKeyResponse struct {
	DeviceKey  string
	DeviceCert string
}
