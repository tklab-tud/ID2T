##################################
# DEFINITION OF C++ PROJECT
##################################
project(cpp-pcapreader)

# Define CMake settings
cmake_minimum_required(VERSION 3.2)

IF(NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE "Release")
ENDIF()

IF (CMAKE_BUILD_TYPE MATCHES Debug)
    MESSAGE(STATUS "Running Debug configuration.")
ELSEIF (CMAKE_BUILD_TYPE MATCHES Release)
    MESSAGE(STATUS "Running Release configuration.")
ENDIF()

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the library source files
SET(SOURCE_FILES cxx/pcap_processor.cpp cxx/pcap_processor.h cxx/statistics.cpp cxx/statistics.h cxx/statistics_db.cpp cxx/statistics_db.h cxx/artifacts_tests.h cxx/artifacts_tests.cpp cxx/utilities.h cxx/utilities.cpp)

# Include SQLiteCpp library and build it
option(SQLITECPP_RUN_CPPLINT OFF)
include_directories(SQLiteCpp/include)
add_subdirectory(SQLiteCpp)

# Find libtins library
FIND_LIBRARY(TINS_LIBRARY tins)
IF(TINS_LIBRARY)
  MESSAGE(STATUS "Tins library found in ${TINS_LIBRARY}")
ELSE()
  MESSAGE(FATAL_ERROR "Tins library not found.")
ENDIF()

FIND_PACKAGE(PythonLibs 3.0 REQUIRED)
IF(PYTHONLIBS_FOUND)
  INCLUDE_DIRECTORIES("${PYTHON_INCLUDE_DIRS}")
ELSE()
  MESSAGE(FATAL_ERROR "Unable to find Python libraries.")
ENDIF()

# Find and configure BOOST library
FIND_PACKAGE(Boost 1.54 QUIET)
IF (Boost_FOUND)
    INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}")
    SET(Boost_USE_STATIC_LIBS OFF)
    SET(Boost_USE_MULTITHREADED ON)
    SET(Boost_USE_STATIC_RUNTIME OFF)
    # Find the boost python 3 component
    SET(PYTHON_VERSIONS python3 python-py35 python-py34 python-py33 python-py32)
    FOREACH(VERSION ${PYTHON_VERSIONS})
      FIND_PACKAGE(Boost COMPONENTS ${VERSION} QUIET)
      IF(Boost_FOUND)
        MESSAGE(STATUS "Python Boost found as '${VERSION}'.")
        BREAK()
      ENDIF()
    ENDFOREACH(VERSION)
    IF(NOT Boost_FOUND)
      MESSAGE(FATAL_ERROR "Python Boost component not found.")
    ENDIF()
ELSE ()
    MESSAGE(FATAL_ERROR "Unable to find the Boost libraries (version 1.54 or higher).")
ENDIF ()

SET_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

ADD_LIBRARY(pcapreader SHARED ${SOURCE_FILES})
# Libs pthread and dl are prerequisites of SQLiteCpp
TARGET_LINK_LIBRARIES(pcapreader ${Boost_LIBRARIES} "${TINS_LIBRARY}" SQLiteCpp sqlite3 pthread dl)

# comment this out to build executable (for development)
#ADD_EXECUTABLE(cpp-pcapreader ${SOURCE_FILES})
#TARGET_LINK_LIBRARIES(cpp-pcapreader ${Boost_LIBRARIES} "${TINS_LIBRARY}" SQLiteCpp sqlite3 pthread dl)
