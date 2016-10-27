##################################
# DEFINITION OF C++ PROJECT
##################################
project(cpp-pcapreader)

# Define CMake settings
cmake_minimum_required(VERSION 3.5)

IF (CMAKE_BUILD_TYPE MATCHES Debug)
    MESSAGE(STATUS "Running DEBUG configuration. Skipping library generation.")
ELSEIF (CMAKE_BUILD_TYPE MATCHES Release)
    MESSAGE(STATUS "Running RELEASE configuration. Creating library..")
ENDIF()

#IF(NOT CMAKE_BUILD_TYPE)
#    SET(CMAKE_BUILD_TYPE "DEBUG")
#ENDIF()
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files and build executable cpp-pcapreader
set(SOURCE_FILES cxx/pcap_processor.cpp cxx/pcap_processor.h cxx/statistics.cpp cxx/statistics.h cxx/statistics_db.cpp cxx/statistics_db.h)

# Include SQLiteCpp library and build it
include_directories(SQLiteCpp/include)
add_subdirectory(SQLiteCpp)

# Find libtins library and link it to the executable cpp-pcapreader
# Libs pthread and dl are prerequisites for SQLiteCpp
FIND_LIBRARY(TINS_LIBRARY tins)

# Find and configure BOOST library
FIND_PACKAGE(Boost 1.54.0)
IF (Boost_FOUND AND TINS_LIBRARY)
    INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}" "/usr/include/python3.4m/")
    SET(Boost_USE_STATIC_LIBS OFF)
    SET(Boost_USE_MULTITHREADED ON)
    SET(Boost_USE_STATIC_RUNTIME OFF)

    FIND_PACKAGE(Boost 1.54.0 COMPONENTS "python-py34")

    ADD_EXECUTABLE(cpp-pcapreader ${SOURCE_FILES})
    ADD_LIBRARY(pcapreader SHARED ${SOURCE_FILES})

    # link it to the executable cpp-pcapreader
    # Libs pthread and dl are prerequisites for SQLiteCpp
    TARGET_LINK_LIBRARIES(pcapreader ${Boost_LIBRARIES} "${TINS_LIBRARY}" SQLiteCpp sqlite3 pthread dl)
    TARGET_LINK_LIBRARIES(cpp-pcapreader ${Boost_LIBRARIES} "${TINS_LIBRARY}" SQLiteCpp sqlite3 pthread dl)
ELSE ()
    MESSAGE(FATAL_ERROR "Unable to find correct Boost version and/or Libtins library")
ENDIF ()


# Check if GNUCXX compiler is configured
set_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)
IF(CMAKE_COMPILER_IS_GNUCXX)
	ADD_DEFINITIONS("-Wall")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1")        ## Optimize
ELSE()
	MESSAGE(FATAL_ERROR "CMakeLists.txt has not been tested...")
ENDIF()