#!/bin/bash

FULLBUILD=false
NONINTERACTIVE=false
BUILD_TYPE='Release'
LIBTINS_VERSION=0

while test $# -gt 0
do
    case "$1" in
        --non-interactive)
            NONINTERACTIVE=true
            ;;
        --full)
            FULLBUILD=true
            ;;
        --debug)
            BUILD_TYPE='Debug'
            ;;
    esac
    shift
done

# Install required packages
if [ ! ${NONINTERACTIVE} = true ]; then
    ./resources/install_dependencies.sh
fi

LIBTINS_VERSION=$(./resources/libtins_version.sh)

# Fullbuild or nonexistent venv
if [ ${FULLBUILD} = true -o ! -d .venv ]; then
    rm -Rf .venv
    python3 -m venv .venv
    if [ $? != 0 ]; then
        echo "Error: Could not create the venv. Please make sure the 'venv' Python-module is installed."
        exit
    fi
fi

# Activate the venv
source .venv/bin/activate

# Upgrade pip if necessary
pip3 install --upgrade pip

# Install python packages
pip3 install -r resources/requirements.txt

# Deactivate the venv
deactivate

# Create the Makefile using cmake, from a clean build directory
cd code_boost/src/build/
if [ ${PWD##*/} = 'build' ]; then
    if [ ${FULLBUILD} = true ]; then
        # Only delete everything if we are in a folder called 'build'.
        rm -rf ./*
    fi
else
    echo "Error: The 'build' directory was not found."
    exit
fi

CMAKE_ARGS="-D CMAKE_BUILD_TYPE="${BUILD_TYPE}" -D LIBTINS_VERSION="${LIBTINS_VERSION}

which ninja &>/dev/null
if [ $? != 0 ]; then
    cmake ${CMAKE_ARGS} ..

    # Make sure we're able to get the number of cores
    if [ $(uname) = 'Darwin' ]; then
        NUMCORES=$(sysctl -n hw.logicalcpu)
    else
        NUMCORES=$(nproc)
    fi

    if [ -f Makefile ]; then
        make -j${NUMCORES}
    else
        echo "Error: 'cmake' did not finish successfully."
        exit
    fi
else
    cmake ${CMAKE_ARGS} .. -G Ninja

    if [ -f build.ninja ]; then
        ninja
    else
        echo "Error: 'cmake' did not finish successfully."
        exit
    fi
fi

if [ $? -eq 0 ]; then
    cp libpcapreader.so ../../../code/ID2TLib/
    cp libbotnetcomm.so ../../../code/ID2TLib/Botnet
else
    echo "Error: 'make' did not finish successfully."
    exit
fi

cd ../../../

# Create the ID2T script
cat >./id2t  <<EOF
#!/bin/bash
# Find the executable
if [ $(uname) = 'Darwin' ]; then
    ID2T_DIR=\$(greadlink -f \$0)
else
    ID2T_DIR=\$(readlink -f \$0)
fi
SCRIPT_PATH=\${ID2T_DIR%/*}
# Execute ID2T
source "\$SCRIPT_PATH"/.venv/bin/activate
exec "\$SCRIPT_PATH"/code/CLI.py "\$@"
deactivate
EOF

# Create the test script
cat >./run_tests  <<EOF
#!/bin/bash
# Find the executable
if [ $(uname) = 'Darwin' ]; then
    ID2T_DIR=\$(greadlink -f \$0)
else
    ID2T_DIR=\$(readlink -f \$0)
fi
SCRIPT_PATH=\${ID2T_DIR%/*}
cd \$SCRIPT_PATH
source .venv/bin/activate
# Regenerate the statistics DB
./id2t -i resources/test/reference_1998.pcap -rd >/dev/null
cd code
# Execute tests
set -e
PRINT_COV=true
testpath="discover -s Test/"
if [ -e "Test/test_\$1.py" ]; then
    testpath="Test/test_\$1.py"
    PRINT_COV=false
fi
PYTHONWARNINGS="ignore" python3 -m coverage run --source=. -m unittest \$testpath >/dev/null
if \$PRINT_COV ; then
    python3 -m coverage html
    python3 -m coverage report -m
fi
deactivate
EOF

# Create the test script
cat >./test_efficiency  <<EOF
#!/bin/bash
# Find the executable
if [ $(uname) = 'Darwin' ]; then
    ID2T_DIR=\$(greadlink -f \$0)
else
    ID2T_DIR=\$(readlink -f \$0)
fi
SCRIPT_PATH=\${ID2T_DIR%/*}
TEST_DIR=\${SCRIPT_PATH}/resources/test/
TEST_PCAP=\${TEST_DIR}reference_1998.pcap
PLOT_DIR=\${TEST_DIR}/plot/
cd \${SCRIPT_PATH}/code
error=0
# Execute tests
set +e
python3 -m unittest Test/efficiency_testing.py
error=\$?
cd \$SCRIPT_PATH
source .venv/bin/activate
mkdir \$PLOT_DIR
smbloris="SMBLorisAttack attackers.count=4 packets.per-second=8.0"
smbscan1="SMBScanAttack ip.src=192.168.178.1 ip.dst=192.168.178.10-192.168.179.253"
smbscan2="SMBScanAttack ip.src=192.168.178.1 ip.dst=192.168.178.10-192.168.178.109 hosting.ip=192.168.178.10-192.168.178.109"
ftp="FTPWinaXeExploit ip.src=192.168.178.1 ip.dst=192.168.178.10"
porto="PortscanAttack ip.src=192.168.178.1 port.open=80"
portc="PortscanAttack ip.src=192.168.178.1 port.open=20"
sqli="SQLiAttack ip.dst=192.168.0.1"
joomla="JoomlaRegPrivExploit ip.src=192.168.178.1"
sality="SalityBotnet"
ddos="DDoSAttack attackers.count=10 packets.per-second=95 attack.duration=10"
ms17="MS17Scan ip.src=192.168.178.1"
memcrashed="MemcrashedSpooferAttack"
eb="EternalBlue"
for i in "\$smbloris" "\$smbscan1" "\$smbscan2" "\$ftp" "\$porto" "\$portc" "\$sqli" "\$joomla" "\$sality" "\$ddos" "\$ms17" "\$memcrashed" "\$eb"; do
    mprof run ./id2t -i \${TEST_PCAP} -a \${i}
    mprof plot -t "\${i}" -o "\${PLOT_DIR}\${i}.png"
    mv mprofile_* "\${PLOT_DIR}\${i}.dat"
done
echo "\nPlotted images can be found in \"\${TEST_DIR}\"."
echo "By executing \"mprof plot <file>.dat\" you can get a more detailed look."
deactivate
exit \$error
EOF

chmod +x ./code/CLI.py
chmod +x ./id2t
chmod +x ./run_tests
chmod +x ./test_efficiency

echo -e "\n\nAll is set. ID2T is ready."
echo -e "\nRun efficiency tests with the command './test_efficiency'"
echo -e "Run unit tests with the command './run_tests'"
echo -e "Run ID2T with the command './id2t'"
