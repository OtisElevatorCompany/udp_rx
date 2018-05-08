// +build windows

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
	destip := "192.168.1.101"
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
		ServerConn.ReadFromUDP(buf)
		break
	}
	if buf[0] != 192 || buf[1] != 168 || buf[2] != 1 || buf[3] != 100 {
		t.Errorf("Invalid src ip")
	}
	if buf[4] != 0xD9 || buf[5] != 0x01 {
		t.Errorf("Invalid src prt")
	}
	for i := 0; i < 11; i++ {
		if buf[6+i] != (byte)(10-i) {
			t.Errorf("Data invalid")
		}
	}
}
