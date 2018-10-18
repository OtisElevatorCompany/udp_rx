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
package main

import (
	"testing"

	"./udprxlib"
)

//TestLogConfig checks the logger configuration method
func TestLogConfig(t *testing.T) {
	t0 := 0
	t1 := 1
	t2 := 2
	configLogger(&t0)
	configLogger(&t1)
	configLogger(&t2)
}

func TestModifyForWindows(t *testing.T) {
	confFilePath = ""
	defaultKeyPath = ""
	defaultCertPath = ""
	defaultCACertPath = ""
	modifyDefaultsWindows()
	if confFilePath != "c:\\programdata\\udp_rx\\udp_rx_conf.windows.json" {
		t.Errorf("Error with windows conf path. Path: %s", confFilePath)
	}
	if defaultKeyPath != "c:\\programdata\\udp_rx\\udp_rx.key" {
		t.Errorf("Error with windows key path. Path: %s", defaultKeyPath)
	}
	if defaultCertPath != "c:\\programdata\\udp_rx\\udp_rx.crt" {
		t.Errorf("Error with windows crt path. Path: %s", defaultCertPath)
	}
	if defaultCACertPath != "c:\\programdata\\udp_rx\\ca.crt" {
		t.Errorf("Error with windows ca crt path. Path: %s", defaultCACertPath)
	}
}

func TestSetConfigValues(t *testing.T) {
	// make a confFile with some known values
	conf := udprxlib.ConfFile{
		ListenAddr: "abc",
		KeyPath:    "def",
		CertPath:   "foo",
		CaCertPath: defaultCACertPath,
	}
	defLisAddr := defaultListenAddr
	changedCertArg := "foobar"
	setConfigValues(&conf, &defLisAddr, &defaultKeyPath, &changedCertArg, &defaultCACertPath)
	// listen addr and key path should be set from conf object
	if listenAddr != "abc" {
		t.Errorf("listen address is wrong. Value: %s", listenAddr)
	}
	if keyPath != "def" {
		t.Errorf("keypath is wrong. Value: %s", keyPath)
	}
	// cert arg should be set from command line arg
	if certPath != "foobar" {
		t.Errorf("certpath is wrong. Value: %s", certPath)
	}
	// CaCertPath should be default
	if caCertPath != defaultCACertPath {
		t.Errorf("ca certpath shouldn't have changed. Value: %s", caCertPath)
	}
}
