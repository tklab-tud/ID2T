#!/bin/bash

DEB_PKGS='libqt5opengl5-dev'
RPM_PKGS="cmake make tcpdump coreutils gcc gcc-c++ libpcap-devel python3 python3-devel"
YES=''
PATCH_DIR=../../../resources/patches

while test $# -gt 0
do
    case "$1" in
        -y)
            YES='-y'
            ;;
    esac
    shift
done

install_pkg_arch()
{
    PACMAN_PKGS="gcc make cmake python python-pip sqlite tcpdump cairo"

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    pacman -Qi $PACMAN_PKGS >/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        if [ ${YES} == '-y' ]; then
            YES='--noconfirm'
        fi
        sudo pacman -S ${YES} --needed $PACMAN_PKGS
    else
        echo -e "Packages: Found."
    fi

    libtins_version=$(pacman -Qi libtins | grep "Version" | cut -d : -f 2 | xargs)

    # libtins is not provided by Arch repos, check seperately
    echo -e "Additional Packages: Checking..."
    pacman -Qi libtins >/dev/null
    if [ $? != 0 ] || [ ${libtins_version:0:3} != "4.2" ]; then
        echo -e "Additional Packages: Installing..."

        pushd /tmp

        # Download fresh copy of libtins
        wget "https://aur.archlinux.org/cgit/aur.git/snapshot/libtins.tar.gz"
        tar -xzf libtins.tar.gz
        rm libtins.tar.gz

        pushd libtins

        # Build and install
        makepkg -si

        popd
        rm -R libtins
        popd
    else
        echo -e "Additional Packages: Found."
    fi
}

install_pkg_fedora()
{
    DNF_PKGS="sqlite sqlite-devel openssl-devel boost-devel cairo"

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    rpm -q ${DNF_PKGS} ${RPM_PKGS} >/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        sudo dnf install ${YES} ${DNF_PKGS} ${RPM_PKGS}
    else
        echo -e "Packages: Found."
    fi
}

install_pkg_suse()
{
    ZYPPER_PKGS="sqlite3 sqlite3-devel libboost_headers-devel libopenssl-devel libcairo2"

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    rpm -q ${ZYPPER_PKGS} ${RPM_PKGS} >/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        sudo zypper install ${YES} --download-as-needed ${ZYPPER_PKGS} ${RPM_PKGS}
    else
        echo -e "Packages: Found."
    fi
}

install_pkg_ubuntu()
{
    APT_PKGS='build-essential cmake python3-dev python3-pip python3-venv sqlite tcpdump libpcap-dev libcairo2-dev'

    if [ "$OS" = 'ubuntu' ] && [ "$VERSION" = '16.04' ]; then
        DEB_LIBTINS='libtins-dev'
    fi

    which sudo >/dev/null
    if [ $? != 0 ]; then
        # sudo wasn't found, so we use su
        SUDO="su -c "
    else
        SUDO=sudo
    fi

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    dpkg -s $APT_PKGS $DEB_PKGS &>/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        $SUDO apt-get install ${YES} $APT_PKGS $DEB_PKGS $DEB_LIBTINS
    else
        echo -e "Packages: Found."
    fi
}

install_pkg_darwin()
{
    BREW_PKGS="cmake python coreutils libdnet libtins sqlite cairo"

    brew unlink python@2

    # Check first to avoid unnecessary update
    echo -e "Packages: Checking..."
    brew ls --versions $BREW_PKGS &>/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        brew install $BREW_PKGS
        echo -e "Packages: Upgrading..."
        brew upgrade $BREW_PKGS
    else
        echo -e "Packages: Found."
    fi
}

# Make sure the submodules are there
echo -e "Updating submodules"
git submodule update --init --recursive

KERNEL=$(uname)

if [ "$KERNEL" = 'Darwin' ]; then
    echo -e "Detected OS: macOS"

    which brew >/dev/null
    if [ $? != 0 ]; then
        echo -e "Brew not found, please install it manually!"
        exit 1
    fi

    install_pkg_darwin
    exit 0
elif [ "$KERNEL" = 'Linux' ]; then
    # Kernel is Linux, check for supported distributions
    OS=$(awk '/^ID=/' /etc/os-release | sed 's/ID=//' | sed 's/"//g' | tr '[:upper:]' '[:lower:]')
    OS_LIKE=$(awk '/ID_LIKE=/' /etc/os-release | sed 's/ID_LIKE=//' | sed 's/"//g' | tr '[:upper:]' '[:lower:]' | cut -d ' ' -f 1)

    if [ -z "$OS_LIKE" ]; then
        # This distribution is missing the os-release file, so try lsb_release
        OS_LIKE=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    fi

    supported='debian ubuntu arch archlinux fedora suse opensuse'
    if ! [[ $supported =~ (^|[[:space:]])$OS_LIKE($|[[:space:]]) ]]; then
        OS_LIKE=${OS}
        DEB_PKGS='libffi-dev'
    fi

    case ${OS_LIKE} in
        archlinux|arch)
            echo -e "Detected OS: Arch Linux"
            install_pkg_arch
            exit 0
            ;;
        debian|ubuntu)
            echo -e "Detected OS: Debian"
            install_pkg_ubuntu
            exit 0
            ;;
        suse|opensuse)
            echo -e "Detected OS: openSuse"
            install_pkg_suse
            exit 0
            ;;
        fedora)
            echo -e "Detected OS: Fedora"
            install_pkg_fedora
            exit 0
            ;;
    esac
fi

echo -e "Your OS ("${OS_LIKE}") is not supported by this script, please make sure to install the dependencies manually"
exit 0
