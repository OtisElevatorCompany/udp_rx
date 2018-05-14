// +build linux

package main

import (
	"net"
	"testing"
)

func TestCreateUDPSocket(t *testing.T) {
	err := CreateUDPSocket()
	if err != nil {
		t.Errorf("Failed to create a socket")
	}
}

func TestSendUDP(t *testing.T) {
	go handleUDPConn(t)
	srcip := "192.168.1.100"
	destip := "127.0.0.1"
	var srcprt uint = 55553
	var destprt uint = 55552
	databuf := make([]byte, 11)
	for i := 0; i < 11; i++ {
		databuf[i] = (byte)(10 - i)
	}
	SendUDP(srcip, destip, srcprt, destprt, databuf, 0)
}
func handleUDPConn(t *testing.T) {
	listenAddr := ":55552"
	ServerAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
	ServerConn, _ := net.ListenUDP("udp", ServerAddr)
	defer ServerConn.Close()
	buf := make([]byte, 1024)
	for {
		_, src, _ := ServerConn.ReadFromUDP(buf)
		if src.IP.String() != "192.168.1.100" {
			t.Errorf("src IP invalid: %s", src.IP.String())
		}
		if src.Port != 55553 {
			t.Errorf("src Port invalid %d", src.Port)
		}
		break
	}
	for i := 0; i < 11; i++ {
		if buf[i] != (byte)(10-i) {
			t.Errorf("Data invalid")
		}
	}
}
