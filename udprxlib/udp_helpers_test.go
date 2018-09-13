package udprxlib

import (
	"testing"
)

func TestIPChecksum(t *testing.T) {
	ip := Iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: 0x11,
	}
	ip.Checksum()
	if ip.csum != 0 {
		t.Error("non zero checksum")
	}
}

func TestUDPChecksum(t *testing.T) {
	ip := Iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: 0x11,
	}
	udp := Udphdr{
		src: uint16(1),
		dst: uint16(2),
	}
	udp.Checksum(&ip, []byte{1, 2, 3, 4, 5})
	if udp.csum != 0 {
		t.Error("non zero checksum")
	}
}

func TestParseIpSuccess(t *testing.T) {
	ip1, ip2, err := ParseIps("192.168.1.1", "191.168.1.10")
	if err != nil {
		t.Error("Error parsing good ip addresses")
	}
	if ip1.To4()[0] != 192 {
		t.Error("error with msb of ip 1")
	}
	if ip2.To4()[0] != 191 {
		t.Error("error with msb of ip 2")
	}
}

func TestParseIpFail(t *testing.T) {
	_, _, err := ParseIps("192.168.1", "191.168.1.10")
	if err == nil {
		t.Error("ip 1 should have failed")
	}
}
func TestParseIpFail2(t *testing.T) {
	_, _, err := ParseIps("192.168.1.250", "191.168.1")
	if err == nil {
		t.Error("ip 2 should have failed")
	}
}
