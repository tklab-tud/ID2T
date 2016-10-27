# CMake generated Testfile for 
# Source directory: /mnt/hgfs/vm-exchange/SQLiteCpp
# Build directory: /mnt/hgfs/vm-exchange/SQLiteCpp/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
ADD_TEST(UnitTests "SQLiteCpp_tests")
ADD_TEST(Example1Run "SQLiteCpp_example1")
SUBDIRS(sqlite3)
SUBDIRS(googletest)
