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

// Package udprxlib is the driver for udprx
package udprxlib

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// // ClientHostNameValidate performs a
// func ClientHostNameValidate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
// 	//copied from the default options in src/crypto/tls/handshake_server.go, 680 (go 1.11)
// 	opts := x509.VerifyOptions{
// 		Roots:         c.config.ClientCAs,
// 		CurrentTime:   c.config.time(),
// 		Intermediates: x509.NewCertPool(),
// 		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
// 	}

// 	roots := x509.NewCertPool()
// 	for _, rawCert := range rawCerts {
// 		cert, _ := x509.ParseCertificate(rawCert)
// 		roots.AddCert(cert)
// 	}
// 	opts := x509.VerifyOptions{
// 		Roots: roots,
// 	}
// 	_, err := cert.Verify(opts)
// 	return err
// }

// func ClientHNValidate(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
// 	hi := helloInfo
// 	serverConf := &tls.Config{
// 		VerifyPeerCertificate: getClientValidator(hi, serverConf),
// 	}
// 	return serverConf, nil
// }

// GetClientValidator does a thing
func getClientValidator(helloInfo *tls.ClientHelloInfo, c *tls.Config) func([][]byte, [][]*x509.Certificate) error {
	log.Debug("AHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		//copied from the default options in src/crypto/tls/handshake_server.go, 680 (go 1.11)
		//but added DNSName
		fmt.Println("EWOIFJOWEIFJWOIEWJFWOIEJF")
		log.Debug("tls config in validator: ", c)
		opts := x509.VerifyOptions{
			Roots:         c.ClientCAs,
			CurrentTime:   c.Time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			DNSName:       helloInfo.Conn.RemoteAddr().String(),
		}
		_, err := verifiedChains[0][0].Verify(opts)
		return err
	}
}

// GetServerConfig returns a udp_rx TLS server configuration
func GetServerConfig(rootCAs *x509.CertPool, cer tls.Certificate) *tls.Config {
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	serverConf.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		serverConf := &tls.Config{
			VerifyPeerCertificate: getClientValidator(hi, serverConf),
		}
		return serverConf, nil
	}
	return serverConf
}
