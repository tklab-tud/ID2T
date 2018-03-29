#!/bin/bash

# Install required packages
if [ "$1" != '--non-interactive' ]; then
    ./resources/install_dependencies.sh
fi

# Create the Makefile using cmake, from a clean build directory
cd code_boost/src/build/
if [ ${PWD##*/} = 'build' ]; then
    # Only delete everything if we are in a folder called 'build'.
    rm -rf ./*
else
    echo "Error: The 'build' directory was not found."
    exit
fi
cmake ..

# Make sure we're able to get the number of cores
if [ $(uname) = 'Darwin' ]; then
    NUMCORES=$(sysctl -n hw.logicalcpu)
else
    NUMCORES=$(nproc)
fi

if [ -f Makefile ]; then
    make -j$NUMCORES
else
    echo "Error: 'cmake' did not finish successfully."
    exit
fi

if [ $? -eq 0 ]; then
    cp libpcapreader.so ../../../code/ID2TLib/
else
    echo "Error: 'make' did not finish successfully."
    exit
fi

cd ../../../

# Create the ID2T script
cat >./id2t  <<EOF
#!/bin/sh
# Find the executable
if [ $(uname) = 'Darwin' ]; then
    alias readlink='greadlink'
fi
ID2T_DIR=\$(readlink -f \$0)
SCRIPT_PATH=\${ID2T_DIR%/*}
cd \$SCRIPT_PATH
# Execute ID2T
exec ./code/CLI.py "\$@"
EOF

# Create the test script
cat >./run_tests  <<EOF
#!/bin/sh
# Find the executable
if [ $(uname) = 'Darwin' ]; then
    alias readlink='greadlink'
fi
ID2T_DIR=\$(readlink -f \$0)
SCRIPT_PATH=\${ID2T_DIR%/*}
cd \$SCRIPT_PATH
# Regenerate the statistics DB
./id2t -i resources/test/reference_1998.pcap -r >/dev/null
cd code
# Execute tests
set -e
PRINT_COV=true
testpath="discover -s Test/"
if [ -e "Test/test_\$1.py" ]; then
    testpath="Test/test_\$1.py"
    PRINT_COV=false
fi
PYTHONWARNINGS="ignore" coverage3 run --source=. -m unittest \$testpath >/dev/null
if \$PRINT_COV ; then
    coverage3 html
    coverage3 report -m
fi
EOF

# Create the test script
cat >./test_efficiency  <<EOF
#!/bin/sh
# Find the executable
if [ $(uname) = 'Darwin' ]; then
    alias readlink='greadlink'
fi
ID2T_DIR=\$(readlink -f \$0)
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
eb="EternalBlue"
for i in "\$smbloris" "\$smbscan1" "\$smbscan2" "\$ftp" "\$porto" "\$portc" "\$sqli" "\$joomla" "\$sality" "\$ddos" "\$ms17" "\$eb"; do
    mprof run ./id2t -i \${TEST_PCAP} -a \${i}
    mprof plot -t "\${i}" -o "\${PLOT_DIR}\${i}.png"
    mv mprofile_* "\${PLOT_DIR}\${i}.dat"
done
echo "\nPlotted images can be found in \"\${TEST_DIR}\"."
echo "By executing \"mprof plot <file>.dat\" you can get a more detailed look."
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
