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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var serverCert *tls.Certificate
var rootCAs *x509.CertPool

// GetServerConfig returns a udp_rx TLS server configuration that validates
// Client Certificates for signing by the root CA as well as their connecting IP
// address
func GetServerConfig(rcas *x509.CertPool, sc *tls.Certificate) *tls.Config {
	serverCert = sc
	rootCAs = rcas
	serverConf := &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return serverCert, nil
		},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			serverConf := &tls.Config{
				GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return serverCert, nil
				},
				MinVersion:            tls.VersionTLS13,
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             rootCAs,
				VerifyPeerCertificate: getClientValidator(hi),
			}
			return serverConf, nil
		},
	}
	return serverConf
}

// getClientValidator is a closure which provides connection info to VerifyPeerCertificate
// in the TLS configuration
func getClientValidator(helloInfo *tls.ClientHelloInfo) func([][]byte, [][]*x509.Certificate) error {
	log.Debug("Inside get client validator")
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		//copied from the default options in src/crypto/tls/handshake_server.go, 680 (go 1.11)
		//but added DNSName
		log.Debug("tls config in validator")
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			DNSName:       strings.Split(helloInfo.Conn.RemoteAddr().String(), ":")[0],
		}
		_, err := verifiedChains[0][0].Verify(opts)
		return err
	}
}
