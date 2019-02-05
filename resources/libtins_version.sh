#!/bin/bash
libtins_version="0"

KERNEL=$(uname)

if [ "$KERNEL" = 'Darwin' ]; then
    #libtins_version="4.1"
    libtins_version=$(brew info libtins | grep "libtins:" | cut -d " " -f 3)
elif [ "$KERNEL" = 'Linux' ]; then
    libtins_version=$(pkg-config --modversion libtins)
fi

echo ${libtins_version}

exit 0
