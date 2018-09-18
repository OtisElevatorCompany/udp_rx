package udprxlib

import "testing"

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
	if conf.CertPath != "/etc/udp_rx/udp_rx.cert" {
		t.Error("Wrong cert path")
	}
	if conf.CaCertPath != "/etc/udp_rx/ca.cert.pem" {
		t.Errorf("Wrong ca path. Path: %s", conf.CaCertPath)
	}
}
