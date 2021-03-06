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

// Package udprxlib is the driver for udprx
package udprxlib

import (
	"os"
	"time"
)

var getTime = time.Now().UTC().UnixNano

func intToBytes(input int) []byte {
	// this must be less than 1024 so we only have a few use cases
	output := make([]byte, 2)
	lower := input & 0xFF
	output[1] = byte(lower)
	upper := (input >> 8) & 0xFF
	output[0] = byte(upper)
	return output
}

func getTimeBytes() []byte {
	barray := make([]byte, 8)
	time := getTime()
	barray[0] = byte((time >> 56) & 0xFF)
	barray[1] = byte((time >> 48) & 0xFF)
	barray[2] = byte((time >> 40) & 0xFF)
	barray[3] = byte((time >> 32) & 0xFF)
	barray[4] = byte((time >> 24) & 0xFF)
	barray[5] = byte((time >> 16) & 0xFF)
	barray[6] = byte((time >> 8) & 0xFF)
	barray[7] = byte(time & 0xFF)
	return barray
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
