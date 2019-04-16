#### Supported Systems
The following operating systems are currently supported by the dependency installation script and are continuously tested with TravisCI.
* Linux Distributions
    - ArchLinux
    - Debian 9
    - Fedora 29
    - Kali Linux 2018.4
    - OpenSUSE
        - Leap 15
        - Tumbleweed
    - Ubuntu
        - 16.04
        - 18.04
        - 18.10
* macOS
    - High Sierra
    - Sierra

In general every Debian-, Ubuntu- or ArchLinux-based distribution should work out of the box. If you have trouble with any of the listed operating systems or their "children" first checkout the dependency installation script or the readme for the packages required by your system and try to install them manually. If this does not work either, feel free to open an issue including the output of the dependency installation script, your distributions name and its version.

Also feel free to suggest Linux distributions to support in the future in [issue #83](https://github.com/tklab-tud/ID2T/issues/83) or even [contribute](./CONTRIBUTORS.md#how-to-contribute) to the script via pull request.

#### Manually Tested
The following operating systems were hand tested by developers, but do not have an official docker image for integration into TravisCI.
* Antergos
* LinuxMint 19.1
* macOS Mojave
* Manjaro 18.0
* MXLinux 18.1
* Zorin OS (possibly outdated)

#### Unsupported Systems
The following operating systems are not and will most likely never be supported by the dependency installation script. This is due to outdated core dependencies in their repositories.
* Debian 8 or older
* Red Hat

