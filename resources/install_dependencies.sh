#!/bin/bash

install_pkg_arch()
{
    PACMAN_PKGS="boost boost-libs cmake python python-pip sqlite tcpdump"

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
    APT_PKGS="build-essential libboost-dev libboost-python-dev cmake python3-dev python3-pip sqlite tcpdump libtins-dev libpcap-dev"

    # Check first to avoid unnecessary sudo
    echo -e "Packages: Checking..."
    dpkg -s $APT_PKGS &>/dev/null
    if [ $? != 0 ]; then
        # Install all missing packages
        echo -e "Packages: Installing..."
        sudo apt-get install $APT_PKGS
    else
        echo -e "Packages: Found."
    fi
}

install_pkg_darwin()
{
    BREW_PKGS="cmake python coreutils libdnet libtins boost boost-python --with-python3"

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

install_pip()
{
    PYTHON_MODULES="lea numpy matplotlib scapy-python3 scipy coverage"
    echo -e "Python modules: Checking..."

    # Check first to avoid unnecessary sudo
    echo $PYTHON_MODULES | xargs -n 1 pip3 show >/dev/null
    if [ $? == 0 ]; then
        echo -e "Python modules: Found."
        return
    fi

    # Install all missing packages
    echo -e "Python modules: Installing..."
    if [ $KERNEL == 'Darwin' ]; then
        pip3 install $PYTHON_MODULES
    else
        sudo pip3 install $PYTHON_MODULES
    fi
}

# Make sure the SQLiteCpp submodule is there
echo -e "Updating SQLiteCpp"
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
    install_pip
    exit 0
elif [ "$KERNEL" = 'Linux' ]; then
    # Kernel is Linux, check for supported distributions
    OS=$(awk '/DISTRIB_ID=/' /etc/*-release | sed 's/DISTRIB_ID=//' | sed 's/"//g' | tr '[:upper:]' '[:lower:]')
    OS_LIKE=$(awk '/ID_LIKE=/' /etc/*-release | sed 's/ID_LIKE=//' | sed 's/"//g' | tr '[:upper:]' '[:lower:]')

    if [ "$OS_LIKE" = 'archlinux' ]; then
        echo -e "Detected OS: Arch Linux"
        install_pkg_arch
        install_pip
        exit 0
    elif [ "$OS_LIKE" = 'debian' ]; then
        echo -e "Detected OS: Debian"
        install_pkg_ubuntu
        install_pip
        exit 0
    fi
fi
echo -e "Your OS is not supported by this script, please make sure to install the dependencies manually"
exit 0
