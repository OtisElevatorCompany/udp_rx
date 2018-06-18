package main

import (
	"fmt"
	"os"
	"time"
)

func intToBytes(input int) []byte {
	//this must be less than 1024 so we only have a few use cases
	output := make([]byte, 2)
	lower := input & 0xFF
	output[1] = byte(lower)
	upper := (input >> 8) & 0xFF
	output[0] = byte(upper)
	return output
}

func getTimeBytes() []byte {
	barray := make([]byte, 8)
	time := time.Now().UTC().UnixNano()
	fmt.Printf("time is: %d", time)
	barray[0] = byte((time >> 56) & 0xFF)
	barray[1] = byte((time >> 48) & 0xFF)
	barray[2] = byte((time >> 40) & 0xFF)
	barray[3] = byte((time >> 32) & 0xFF)
	barray[4] = byte((time >> 24) & 0xFF)
	barray[5] = byte((time >> 16) & 0xFF)
	barray[6] = byte((time >> 8) & 0xFF)
	barray[7] = byte(time & 0xFF)
	output := ""
	for _, element := range barray {
		output = output + fmt.Sprintf("%d,", element)
	}
	fmt.Println(output)
	return barray
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
