# ZETLAB ZET030 device library

libzet030 is a reference library for ZET 030

USB communication is based on [libusb-1.0](https://libusb.info).
TCP/IPv4 communication is based on POSIX sockets with select.

## Build

```bash
mkdir build
cd build
cmake ..
make
```

### Linux

Setup udev rule to allow regular user to use USB device:

```bash
sudo echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="2FFD", MODE="0660", TAG+="uaccess"' > /etc/udev/rules.d/50-zetlab.rules

sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Windows

Is is recommended to use [vcpkg](https://vcpkg.io/en/getting-started.html).

Install vcpkg (you may need [Git for Windows](https://git-scm.com/downloads/win)):

```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install pkgconf libusb
```

Then use CMake with toolchain file provided by vcpkg:

```bash
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE="[path to vcpkg]/scripts/buildsystems/vcpkg.cmake"
make
```
