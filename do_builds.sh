echo "Linux x64"
mkdir builds/linux_x64 -p
go build
mv udp_rx builds/linux_x64/

echo "Linux 386"
mkdir builds/linux_386 -p
env GOOS=linux GOARCH=386 go build
mv udp_rx builds/linux_386/

echo "Linux ARM v6+"
mkdir builds/linux_arm_v6 -p
env GOOS=linux GOARCH=arm go build
mv udp_rx builds/linux_arm_v6/

echo "Linux ARM v5"
mkdir builds/linux_arm_v5 -p
env GOOS=linux GOARCH=arm GOARM=5 go build
mv udp_rx builds/linux_arm_v5/

echo "udpr windows x64"
mkdir builds/windows_x64 -p
env GOOS=windows GOARCH=amd64 go build
mv udp_rx.exe builds/windows_x64/
