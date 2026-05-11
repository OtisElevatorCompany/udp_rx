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
	"io/ioutil"
	"strings"
	"testing"

	"github.com/OtisElevatorCompany/udp_rx/udprxlib"
)

// TestLogConfig checks the logger configuration method
func TestLogConfig(t *testing.T) {
	t0 := 0
	t1 := 1
	t2 := 2
	configLogger(&t0)
	configLogger(&t1)
	configLogger(&t2)
}

func TestModifyForWindows(t *testing.T) {
	if !isWindows() {
		t.Skip("Windows-only test")
	}
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

// TestModifyForWindowsSetsDefaultLogPath verifies the Windows-specific log path added after the original defaults tests.
func TestModifyForWindowsSetsDefaultLogPath(t *testing.T) {
	if !isWindows() {
		t.Skip("Windows-only test")
	}
	confFilePath = ""
	defaultKeyPath = ""
	defaultCertPath = ""
	defaultCACertPath = ""
	defaultLogPath = ""

	modifyDefaultsWindows()

	if defaultLogPath != "c:\\programdata\\udp_rx\\udp_rx.log" {
		t.Fatalf("Error with windows log path. Path: %s", defaultLogPath)
	}
}

// TestSetConfigValuesUsesDefaultsWhenConfNil verifies that nil config input preserves program defaults for every path field.
func TestSetConfigValuesUsesDefaultsWhenConfNil(t *testing.T) {
	listenAddr = ""
	keyPath = ""
	certPath = ""
	caCertPath = ""

	listAddrArg := defaultListenAddr
	keyPathArg := defaultKeyPath
	certPathArg := defaultCertPath
	caCertPathArg := defaultCACertPath

	setConfigValues(nil, &listAddrArg, &keyPathArg, &certPathArg, &caCertPathArg)

	if listenAddr != defaultListenAddr {
		t.Fatalf("listen address should fall back to default. Value: %s", listenAddr)
	}
	if keyPath != defaultKeyPath {
		t.Fatalf("key path should fall back to default. Value: %s", keyPath)
	}
	if certPath != defaultCertPath {
		t.Fatalf("cert path should fall back to default. Value: %s", certPath)
	}
	if caCertPath != defaultCACertPath {
		t.Fatalf("ca cert path should fall back to default. Value: %s", caCertPath)
	}
}

// TestDefaultLogPathRemainsLinuxDefault verifies the non-Windows default log path introduced 
// for SysV-style Linux installs.
func TestDefaultLogPathRemainsLinuxDefault(t *testing.T) {
	//defaultLogPath = "/var/log/udp_rx.log"

	if !isWindows() && defaultLogPath != "/var/log/udp_rx.log" {
		t.Fatalf("expected Linux default log path /var/log/udp_rx.log, got %s", defaultLogPath)
	}
}

// TestInitDScriptUsesUsrBinBinaryPath verifies the checked-in SysV init.d script starts the 
// installed binary from /usr/bin.
func TestInitDScriptUsesUsrBinBinaryPath(t *testing.T) {
	content, err := ioutil.ReadFile("./init.d/udp-rx-init.sh")
	if err != nil {
		t.Fatalf("failed to read init.d script: %v", err)
	}
	script := string(content)

	if !strings.Contains(script, "if [ -f /usr/bin/udp_rx ]") {
		t.Fatal("expected init.d script to check for /usr/bin/udp_rx before starting")
	}
	if !strings.Contains(script, "/usr/bin/udp_rx >> /dev/null 2>&1 &") {
		t.Fatal("expected init.d script to launch /usr/bin/udp_rx")
	}
}

// TestInitDScriptUsageDocumentsSupportedCommands verifies the checked-in SysV init.d script 
// still documents the supported service actions.
func TestInitDScriptUsageDocumentsSupportedCommands(t *testing.T) {
	content, err := ioutil.ReadFile("./init.d/udp-rx-init.sh")
	if err != nil {
		t.Fatalf("failed to read init.d script: %v", err)
	}
	script := string(content)

	if !strings.Contains(script, "start)") {
		t.Fatal("expected init.d script to support start action")
	}
	if !strings.Contains(script, "stop)") {
		t.Fatal("expected init.d script to support stop action")
	}
	if !strings.Contains(script, "restart)") {
		t.Fatal("expected init.d script to support restart action")
	}
	if !strings.Contains(script, "Usage: udp-rx-init.sh { start | stop | restart }") {
		t.Fatal("expected init.d script usage text to document start, stop, and restart")
	}
}

// TestConfigLoggerDebugInitializesForwardMap verifies that debug logging enables the 
// forward-count map used by packet forwarding diagnostics.
func TestConfigLoggerDebugInitializesForwardMap(t *testing.T) {
	oldForwardMap := udprxlib.ForwardMap
	t.Cleanup(func() {
		udprxlib.ForwardMap = oldForwardMap
	})

	udprxlib.ForwardMap = nil
	debugFlag := 2

	if err := configLogger(&debugFlag); err != nil {
		t.Fatalf("configLogger returned an unexpected error: %v", err)
	}
	if udprxlib.ForwardMap == nil {
		t.Fatal("expected debug logging to initialize ForwardMap")
	}
	udprxlib.ForwardMap["127.0.0.1:55554"] = 1
	if udprxlib.ForwardMap["127.0.0.1:55554"] != 1 {
		t.Fatal("expected initialized ForwardMap to be writable")
	}
}

// TestConfigLoggerNonDebugLeavesForwardMapDisabled verifies that non-debug logging does not 
// enable ForwardMap when it starts disabled.
func TestConfigLoggerNonDebugLeavesForwardMapDisabled(t *testing.T) {
	oldForwardMap := udprxlib.ForwardMap
	t.Cleanup(func() {
		udprxlib.ForwardMap = oldForwardMap
	})

	udprxlib.ForwardMap = nil
	warnFlag := 0

	if err := configLogger(&warnFlag); err != nil {
		t.Fatalf("configLogger returned an unexpected error: %v", err)
	}
	if udprxlib.ForwardMap != nil {
		t.Fatal("expected non-debug logging not to initialize ForwardMap")
	}

	infoFlag := 1
	if err := configLogger(&infoFlag); err != nil {
		t.Fatalf("configLogger returned an unexpected error: %v", err)
	}
	if udprxlib.ForwardMap != nil {
		t.Fatal("expected info logging not to initialize ForwardMap")
	}
}
