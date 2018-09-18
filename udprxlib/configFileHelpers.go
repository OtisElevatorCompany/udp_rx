package udprxlib

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// ConfFile represents the config file struct
type ConfFile struct {
	ListenAddr string `json:"listenAddr"`
	KeyPath    string `json:"keyPath"`
	CertPath   string `json:"certPath"`
	CaCertPath string `json:"caCertPath"`
}

// ParseConfig parses a ConfFile into it's struct
func ParseConfig(path string) (ConfFile, error) {
	jsonFile, err := os.Open(path)
	if err != nil {
		return ConfFile{}, err
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return ConfFile{}, err
	}
	var conf ConfFile
	err = json.Unmarshal(byteValue, &conf)
	return conf, nil
}
