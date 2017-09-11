cmake_minimum_required(VERSION 3.7)
project(cxx)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        pcap_processor.cpp
        pcap_processor.h
        statistics.cpp
        statistics.h
        statistics_db.cpp
        statistics_db.h
        artifacts_tests.cpp
        artifacts_tests.h
        utilities.cpp
        utilities.h)

add_executable(cxx ${SOURCE_FILES})
