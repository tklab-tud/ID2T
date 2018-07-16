#!/bin/bash

install_pkg_arch()
{
    PACMAN_PKGS="cmake python python-pip sqlite tcpdump"

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    pacman -Qi $PACMAN_PKGS >/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        sudo pacman -S --needed $PACMAN_PKGS
    else
        echo -e "Packages: Found."
    fi

    # libtins is not provided by Arch repos, check seperately
    echo -e "Additional Packages: Checking..."
    pacman -Qi libtins >/dev/null
    if [ $? != 0 ]; then
        echo -e "Additional Packages: Installing..."

        pushd /tmp

        # Download fresh copy of libtins
        wget "https://aur.archlinux.org/cgit/aur.git/snapshot/libtins.tar.gz"
        tar -xzf libtins.tar.gz
        rm libtins.tar.gz
        rm -R libtins

        pushd libtins

        # Build and install
        makepkg -si

        popd
        popd
    else
        echo -e "Additional Packages: Found."
    fi
}

install_pkg_ubuntu()
{
    APT_PKGS='build-essential cmake python3-dev python3-pip python3-venv sqlite tcpdump libtins-dev libpcap-dev'

    which sudo >/dev/null
    if [ $? != 0 ]; then
        # sudo wasn't found, so we use su
        SUDO="su -c "
    else
        SUDO=sudo
    fi

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    dpkg -s $APT_PKGS &>/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        $SUDO apt-get install $APT_PKGS
    else
        echo -e "Packages: Found."
    fi
}

install_pkg_darwin()
{
    BREW_PKGS="cmake python coreutils libdnet libtins sqlite"

    # Check first to avoid unnecessary update
    echo -e "Packages: Checking..."
    brew ls --versions $BREW_PKGS &>/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        brew install $BREW_PKGS
    else
        echo -e "Packages: Found."
    fi
}

# Make sure the submodules are there
echo -e "Updating submodules"
git submodule update --init

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
    OS=$(awk '/DISTRIB_ID=/' /etc/*-release | sed 's/DISTRIB_ID=//' | sed 's/"//g' | tr '[:upper:]' '[:lower:]')
    OS_LIKE=$(awk '/ID_LIKE=/' /etc/*-release | sed 's/ID_LIKE=//' | sed 's/"//g' | tr '[:upper:]' '[:lower:]')

    if [ -z "$OS_LIKE" ]; then
        # This distribution is missing the os-release file, so try lsb_release
        OS_LIKE=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    fi

    case $OS_LIKE in
        archlinux|arch)
            echo -e "Detected OS: Arch Linux"
            install_pkg_arch
            exit 0
            ;;
        debian)
            echo -e "Detected OS: Debian"
            install_pkg_ubuntu
            exit 0
            ;;
    esac
fi
echo -e "Your OS is not supported by this script, please make sure to install the dependencies manually"
exit 0
