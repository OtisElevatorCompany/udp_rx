package udprxlib

import "testing"

func TestIntToBytes(t *testing.T) {
	bytes := intToBytes(1)
	if bytes[0] != 0 {
		t.Error("wrong byte order")
	}
}
func TestIntoToBytesFull(t *testing.T) {
	bytes := intToBytes(1025)
	if bytes[0] != 0x04 {
		t.Error("wrong byte order or wrong value")
	}
	if bytes[1] != 0x01 {
		t.Error("Wrong lower side")
	}
}

func TestGetTimeBytes(t *testing.T) {
	getTime = returnTime
	timeBytes := getTimeBytes()
	goodtimeBytes := []byte{17, 116, 239, 237, 171, 24, 96, 0}
	for index := range timeBytes {
		if timeBytes[index] != goodtimeBytes[index] {
			t.Error("Wrong Time")
		}
	}
}
func returnTime() int64 {
	return 1257894000000000000
}
