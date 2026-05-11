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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestCreateCert(t *testing.T) {
	var outputpath, caKeyPath, caCertPath string
	if isWindows() {
		outputpath = "..\\keys\\server.key"
		caKeyPath = "..\\keys\\ca.key"
		caCertPath = "..\\keys\\ca.crt"
	} else {
		outputpath = "../keys/server.key"
		caKeyPath = "../keys/ca.key"
		caCertPath = "../keys/ca.crt"
	}
	err := CreateCert("server.crt", outputpath, caKeyPath, caCertPath, "")
	if err != nil {
		log.Fatal("failed to create/sign server.crt", err)
	}
}

func TestEncryptedCert(t *testing.T) {
	var outputpath, caKeyPath, caCertPath string
	if isWindows() {
		outputpath = "..\\keys\\encrypted_keys\\server.key"
		caKeyPath = "..\\keys\\encrypted_keys\\ca.key"
		caCertPath = "..\\keys\\encrypted_keys\\ca.crt"
	} else {
		outputpath = "../keys/encrypted_keys/server.key"
		caKeyPath = "../keys/encrypted_keys/ca.key"
		caCertPath = "../keys/encrypted_keys/ca.crt"
	}
	err := CreateCert("server.crt", outputpath, caKeyPath, caCertPath, "N0y#Xr7mwy")
	if err != nil {
		log.Fatal("failed to create/sign server.crt", err)
	}
}

func TestCreateCertInMemory(t *testing.T) {
	caKeyPath := "..\\keys\\ca.key"
	caCertPath := "..\\keys\\ca.crt"
	if !isWindows() {
		caKeyPath = strings.Replace(caKeyPath, "\\", "/", -1)
		caCertPath = strings.Replace(caCertPath, "\\", "/", -1)
	}
	var ips []net.IP
	ips = append(ips, net.IPv4(8, 8, 8, 8))
	var hostnames []string
	hostnames = append(hostnames, "example.com")
	newcert, newkey, err := CreateCertInMemory(caKeyPath, caCertPath, "", ips, nil)
	if err != nil {
		log.Fatal("failed to create certs in memory")
	}
	newcertstring := string(newcert)
	newkeystring := string(newkey)
	_ = newcertstring
	_ = newkeystring
}

// TestCreateCertInMemoryIncludesHostnamesAndIPs verifies that generated in-memory certificates preserve both IP and DNS SAN entries.
func TestCreateCertInMemoryIncludesHostnamesAndIPs(t *testing.T) {
	caKeyPath, caCertPath := writeTestCAFiles(t)
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	hostnames := []string{"example.com", "localhost"}

	newcert, _, err := CreateCertInMemory(caKeyPath, caCertPath, "", ips, hostnames)
	if err != nil {
		t.Fatalf("failed to create certs in memory: %v", err)
	}

	block, _ := pem.Decode(newcert)
	if block == nil {
		t.Fatal("expected pem encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(ips[0]) {
		t.Fatalf("generated certificate IP SANs mismatch: %+v", cert.IPAddresses)
	}
	if len(cert.DNSNames) != len(hostnames) {
		t.Fatalf("generated certificate DNS SANs mismatch: %+v", cert.DNSNames)
	}
	for index, hostname := range hostnames {
		if cert.DNSNames[index] != hostname {
			t.Fatalf("generated certificate missing hostname %q in %+v", hostname, cert.DNSNames)
		}
	}
}

// writeTestCAFiles creates a temporary CA keypair on disk for tests that need isolated certificate fixtures.
func writeTestCAFiles(t *testing.T) (string, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "udp-rx-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create test CA certificate: %v", err)
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatalf("failed to marshal test CA key: %v", err)
	}

	tempDir, err := ioutil.TempDir("", "udp-rx-ca")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})
	keyPath := filepath.Join(tempDir, "ca.key")
	certPath := filepath.Join(tempDir, "ca.crt")
	if err := ioutil.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER}), 0600); err != nil {
		t.Fatalf("failed to write test CA key: %v", err)
	}
	if err := ioutil.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatalf("failed to write test CA cert: %v", err)
	}

	return keyPath, certPath
}

// This validates the in-memory certificate generator used for TLS credentials.
// It confirms the generated cert and key load as a valid TLS key pair, include both
// ClientAuth and ServerAuth extended key usages, retain DigitalSignature key usage,
// preserve the IP SAN, and verify correctly against the generated DNS SAN.
func TestCreateCertInMemorySetsMutualTLSUsages(t *testing.T) {
	caKeyPath, caCertPath := writeTestCAFiles(t)
	certPEM, keyPEM, err := CreateCertInMemory(caKeyPath, caCertPath, "", []net.IP{net.ParseIP("127.0.0.1")}, []string{"udp-rx-device"})
	if err != nil {
		t.Fatalf("failed to create certificate in memory: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("expected generated certificate and key to form a valid TLS key pair: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("expected PEM encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatal("expected generated certificate to include client auth usage")
	}
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("expected generated certificate to include server auth usage")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("expected generated certificate to allow digital signatures")
	}
	if !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected generated certificate to keep IP SAN, got %+v", cert.IPAddresses)
	}
	if err := cert.VerifyHostname("udp-rx-device"); err != nil {
		t.Fatalf("expected generated certificate to verify its DNS SAN: %v", err)
	}
}

func containsExtKeyUsage(usages []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == want {
			return true
		}
	}
	return false
}
