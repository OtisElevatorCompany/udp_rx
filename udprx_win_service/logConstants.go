package main

const (
	unexpectedControlRequest uint32 = 1
	serviceFailed            uint32 = 2
	startingService          uint32 = 3
	parsingConfigFile        uint32 = 4
	deviceKeyCertLoading     uint32 = 5
	configurationFileError   uint32 = 6
	udpThreadStopped         uint32 = 7
	tcpThreadStopped         uint32 = 8
	stopUDPError             uint32 = 9
	stopTCPError             uint32 = 10
	serviceStopped           uint32 = 11
	startArgs                uint32 = 12
)
