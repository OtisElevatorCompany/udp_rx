package udprxlib

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// TestParseConfig tests parsing the config file
func TestParseConfig(t *testing.T) {
	conf, err := ParseConfig("../udp_rx_conf.json")
	if err != nil {
		t.Errorf("Couldn't parse config. Error: %s", err.Error())
		return
	}
	if conf.ListenAddr != "" {
		t.Error("Wrong default listen address")
	}
	if conf.KeyPath != "/etc/udp_rx/udp_rx.key" {
		t.Error("Wrong keypath")
	}
	if conf.CertPath != "/etc/udp_rx/udp_rx.crt" {
		t.Error("Wrong cert path")
	}
	if conf.CaCertPath != "/etc/udp_rx/ca.crt" {
		t.Errorf("Wrong ca path. Path: %s", conf.CaCertPath)
	}
}

// TestParseConfigMissingFile verifies that ParseConfig returns an error when the requested config file does not exist.
func TestParseConfigMissingFile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "udp-rx-config-missing")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	_, err = ParseConfig(filepath.Join(tempDir, "missing.json"))
	if err == nil {
		t.Fatal("expected missing config file to return an error")
	}
}

// TestParseConfigOverrideValues verifies that explicit JSON config values are unmarshaled into the expected fields.
func TestParseConfigOverrideValues(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "udp-rx-config-override")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "override.json")
	configBody := []byte(`{"listenAddr":"127.0.0.1","keyPath":"key.pem","certPath":"cert.pem","caCertPath":"ca.pem"}`)
	if err := ioutil.WriteFile(configPath, configBody, 0600); err != nil {
		t.Fatalf("failed to create override config file: %v", err)
	}

	conf, err := ParseConfig(configPath)
	if err != nil {
		t.Fatalf("expected override config file to parse: %v", err)
	}
	if conf.ListenAddr != "127.0.0.1" {
		t.Fatalf("unexpected listenAddr: %s", conf.ListenAddr)
	}
	if conf.KeyPath != "key.pem" {
		t.Fatalf("unexpected keyPath: %s", conf.KeyPath)
	}
	if conf.CertPath != "cert.pem" {
		t.Fatalf("unexpected certPath: %s", conf.CertPath)
	}
	if conf.CaCertPath != "ca.pem" {
		t.Fatalf("unexpected caCertPath: %s", conf.CaCertPath)
	}
}
