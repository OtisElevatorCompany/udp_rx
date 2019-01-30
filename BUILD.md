# Automated Builds
## Linux
you can run the automated build script which will build all of the supported linux architectures by running:

```shell
python3 build_linux_installers.py
```

This will create a folder named `builds` and place the created builds in that folder.

## Windows
To run the automated windows installer, all you have to do is open the `udp_rx_installer` solution in visual studio (version 2015 or higher) and run the build command. This will automatically build the udp_rx windows service and cert creator.

# Manual builds
To build the udp_rx executable (or any other executable [like udprx_firewall]) for linux run the following command:

```shell
env GOOS=<go os target> GOARCH=<go arch target> go build
```

Where the `GOOS` and `GOARCH` values are an OS and Architecture type as defined here: https://github.com/golang/go/blob/master/src/go/build/syslist.go

Example values for `GOOS` are:
* linux
* android
* windows

Example values for `GOARCH` are:
* amd64
* arm
* 386

### ARM v5
If you are compiling for an ARMv5 processor, or ARM CPU with no hard floating point operator, you should run the following command to build:

```shell
env GOOS=<go os target> GOARCH=arm GOARM=5 go build
```

## Windows
The env command used in the above builds is available only on linux. To build on windows (for any target) the environmental variables must be specified using the `$Env` command in powershell. 

```shell
$Env:GOOS=<go os target>
$Env:GOARCH=<go arch target>
go build
```