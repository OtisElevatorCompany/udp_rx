package main

import "fmt"

type connTimeoutError struct {
	err string
}

func (e *connTimeoutError) Error() string {
	return fmt.Sprintf("connection has timed out")
}
