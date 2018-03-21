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

if [ -f Makefile ]; then
    make
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
cd \$SCRIPT_PATH/code
# Execute tests
set -e
testpath="discover -s Test/"
if [ -e "Test/test_\$1.py" ]; then
    testpath="Test/test_\$1.py"
fi
PYTHONWARNINGS="ignore" coverage3 run --source=. -m unittest \$testpath >/dev/null
coverage3 html
coverage3 report -m
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
cd \$SCRIPT_PATH/code
# Execute tests
set -e
python3 -m unittest Test/efficiency_testing.py
EOF

chmod +x ./code/CLI.py
chmod +x ./id2t
chmod +x ./run_tests
chmod +x ./test_efficiency

echo -e "\n\nAll is set. ID2T is ready."
echo -e "\nRun efficiency tests with the command './test_efficiency'"
echo -e "Run unit tests with the command './run_tests'"
echo -e "Run ID2T with the command './id2t'"
