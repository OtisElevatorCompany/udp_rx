import os
import subprocess
from shutil import copyfile

operating_systems = {
    "linux_x64": {"GOOS": "linux", "GOARCH": "amd64"},
    "linux_386": {"GOOS": "linux", "GOARCH": "386"},
    "linux_arm_v6": {"GOOS": "linux", "GOARCH": "arm"},
    "linux_arm_v5": {"GOOS": "linux", "GOARCH": "arm", "GOARM": "5"},
    "windows_x64": {"GOOS": "windows", "GOARCH": "amd64"},
}
tools = [
    "udp_rx", 
    "udprx_firewall",
    "udp_rx_cert_creator"
]
deps = [
    "github.com/sirupsen/logrus",
    "gopkg.in/natefinch/lumberjack.v2"
]

# get and save the current directory
cwd = os.getcwd()

# get the deps
for dep in deps:
    cmd = ["go", "get", dep]
    buildresult = subprocess.run(cmd)
    if buildresult.returncode != 0:
        print("ERROR Getting dependency: {}".format(dep))

# create the directories
print("Creating Build Directories")
for system, _ in operating_systems.items():
    os.makedirs("builds/{}".format(system), exist_ok=True)
    os.makedirs("udprx_firewall/builds/{}".format(system), exist_ok=True)
    os.makedirs("udp_rx_cert_creator/builds/{}".format(system), exist_ok=True)

# build udp_rx and udprx_firewall
print("doing GO BUILDS")
for system, envargs in operating_systems.items():
    os.chdir(cwd)
    for tool in tools:
        os.chdir(cwd)
        if tool == "udprx_firewall":
            os.chdir("udprx_firewall")
        elif tool == "udp_rx_cert_creator":
            os.chdir("udp_rx_cert_creator")
        # build the build command and run build
        command = ["env"]
        for key, value in envargs.items():
            command.append("{}={}".format(key, value))
        command.append("go")
        command.append("build")
        print("Tool: {}, command: {}".format(tool, command))
        buildresult = subprocess.run(command)
        if buildresult.returncode != 0:
            print("ERROR BUILDING: {}-{}".format(tool, system))
        else:
            # move the build to the builds directory
            if not system.startswith("windows"):
                print("renaming {} to builds/{}/{}".format(tool, system, tool))
                os.rename(tool, "builds/{}/{}".format(system, tool))
            else:
                print("renaming {}.exe to builds/{}/{}.exe".format(tool, system, tool))
                os.rename("{}.exe".format(tool), "builds/{}/{}.exe".format(system, tool))

# move back to the root dir
os.chdir(cwd)

# now that the executables are built, create
# installer directories and start moving files into them
print("Creating Installer Directories")
for system, _ in operating_systems.items():
    os.makedirs("installers/{}".format(system), exist_ok=True)
    # move the executables
    for tool in tools:
        if tool == "udprx_firewall":
            pathprefix = "udprx_firewall/"
        elif tool == "udp_rx_cert_creator":
            pathprefix = "udp_rx_cert_creator/"
        else:
            pathprefix = ""
        if not system.startswith("windows"):
            os.rename("{}builds/{}/{}".format(pathprefix, system, tool), "installers/{}/{}".format(system, tool))
        else:
            os.rename("{}builds/{}/{}.exe".format(pathprefix, system, tool), "installers/{}/{}.exe".format(system, tool))
    # move the install script
    if not system.startswith("windows"):
        copyfile("install_scripts/install_udp_rx.sh", "installers/{}/install_udp_rx.sh".format(system))
    else:
        # TODO: update with windows batch
        pass
    # move the portlist if it exists
    if os.path.isfile("install_scripts/portslist"):
        copyfile("install_scripts/portslist", "installers/{}/portslist".format(system))
    else:
        print("Warning: No portslist found")
    # move the config files
    if not system.startswith("windows"):
        copyfile("udp_rx_conf.json", "installers/{}/udp_rx_conf.json".format(system))
    else:
        copyfile("udp_rx_conf.windows.json", "installers/{}/udp_rx_conf.json".format(system))
    # if on linux, move .service file
    if not system.startswith("windows"):
        copyfile("systemd/udp_rx.service", "installers/{}/udp_rx.service".format(system))

# cleanup
print("cleaning up...")
for system, _ in operating_systems.items():
    os.removedirs("builds/{}".format(system))
    os.removedirs("udprx_firewall/builds/{}".format(system))
    os.removedirs("udp_rx_cert_creator/builds/{}".format(system))
