echo "building udp_rx"
echo "Linux x64"
mkdir builds/udp_rx/linux_x64 -p
go build
mv udp_rx builds/udp_rx/linux_x64/

echo "Linux 386"
mkdir builds/udp_rx/linux_386 -p
env GOOS=linux GOARCH=386 go build
mv udp_rx builds/udp_rx/linux_386/

echo "Linux ARM v6+"
mkdir builds/udp_rx/linux_arm_v6 -p
env GOOS=linux GOARCH=arm go build
mv udp_rx builds/udp_rx/linux_arm_v6/

echo "Linux ARM v5"
mkdir builds/udp_rx/linux_arm_v5 -p
env GOOS=linux GOARCH=arm GOARM=5 go build
mv udp_rx builds/udp_rx/linux_arm_v5/

echo "udpr windows x64"
mkdir builds/udp_rx/windows_x64 -p
env GOOS=windows GOARCH=amd64 go build
mv udp_rx.exe builds/udp_rx/windows_x64/

echo ""
echo "Building udprx_firewall"
echo "Linux x64"
cd udprx_firewall
mkdir ../builds/udprx_firewall/linux_x64 -p
go build
mv udprx_firewall ../builds/udprx_firewall/linux_x64/

echo "Linux 386"
mkdir ../builds/udprx_firewall/linux_386 -p
env GOOS=linux GOARCH=386 go build
mv udprx_firewall ../builds/udprx_firewall/linux_386/

echo "Linux ARM v6+"
mkdir ../builds/udprx_firewall/linux_arm_v6 -p
env GOOS=linux GOARCH=arm go build
mv udprx_firewall ../builds/udprx_firewall/linux_arm_v6/

echo "Linux ARM v5"
mkdir ../builds/udprx_firewall/linux_arm_v5 -p
env GOOS=linux GOARCH=arm GOARM=5 go build
mv udprx_firewall ../builds/udprx_firewall/linux_arm_v5/

echo "udpr windows x64"
mkdir ../builds/udprx_firewall/windows_x64 -p
env GOOS=windows GOARCH=amd64 go build
mv udprx_firewall.exe ../builds/udprx_firewall/windows_x64/
