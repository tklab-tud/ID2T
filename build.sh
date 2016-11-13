#!/bin/bash

cd code_boost/src/build/
cmake ..

if [ -f Makefile ]; then
    make
else
    echo "CMake did not finish successfully."
    exit
fi

if [ $? -eq 0 ]; then
    cp libpcapreader.so ../../../code/ID2TLib/
else
    echo "Make did not finish successfully."
    exit
fi

cd ../../../
#ln -s code/CLI.py id2t.py

# Create the ID2T script
cat >./id2t  <<EOF
#!/bin/sh
# Find the executable
ID2T_DIR=\$(readlink -f \$0)
SCRIPT_PATH=\${ID2T_DIR%/*}
cd \$SCRIPT_PATH
# Execute ID2T
exec ./code/CLI.py "\$@"
EOF

chmod +x ./code/CLI.py
chmod +x ./id2t

echo -e "\n\nAll is set. ID2T is ready to be used."
echo -e "\nRun ID2T with the command './id2t'"
