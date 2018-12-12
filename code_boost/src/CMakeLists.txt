##################################
# DEFINITION OF C++ PROJECT
##################################
project(cpp-pcapreader)

# Define CMake settings
cmake_minimum_required(VERSION 3.2)

IF(NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE "Release")
ENDIF()

IF(NOT LIBTINS_VERSION)
   SET(LIBTINS_VERSION "0")
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
SET(SOURCE_FILES cxx/pcap_processor.cpp cxx/pcap_processor.h cxx/statistics.cpp cxx/statistics.h cxx/statistics_db.cpp cxx/statistics_db.h cxx/utilities.h cxx/utilities.cpp)

# Add botnet comm processor source files
SET(BOT_COMM_PROC_SOURCE cxx/botnet_comm_processor.h cxx/botnet_comm_processor.cpp)

# Add the debugging source files
IF (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    SET(DEBUG_FILES cxx/main.cpp cxx/pcap_processor.cpp cxx/pcap_processor.h cxx/statistics.cpp cxx/statistics.h cxx/statistics_db.cpp cxx/statistics_db.h cxx/utilities.h cxx/utilities.cpp)
ENDIF ()

# Include SQLiteCpp library and build it
option(SQLITECPP_RUN_CPPLINT OFF)
include_directories(SQLiteCpp/include)
add_subdirectory(SQLiteCpp)

# Include pybind11
include_directories(pybind11/include)

# Find libtins library
IF(${LIBTINS_VERSION} VERSION_LESS "4.1")
    MESSAGE(STATUS "Tins will be built from source.")
    set(TINS_LIBRARY tins)
    link_directories(BEFORE libtins/src)
    include_directories(libtins/include)
    add_subdirectory(libtins)
    SET_target_properties(${TINS_LIBRARY} PROPERTIES LIBTINS_ENABLE_CXX11 1)
ELSE()
    FIND_LIBRARY(TINS_LIBRARY tins)
    IF(TINS_LIBRARY)
      MESSAGE(STATUS "Tins library found in ${TINS_LIBRARY}")
    ELSE()
      MESSAGE(FATAL_ERROR "Tins library not found.")
    ENDIF()
ENDIF()

FIND_PACKAGE(PythonLibs 3.0 REQUIRED)
IF(PYTHONLIBS_FOUND)
  INCLUDE_DIRECTORIES("${PYTHON_INCLUDE_DIRS}")
  MESSAGE(STATUS "Python includes found in: " ${PYTHON_INCLUDE_DIRS} )
  MESSAGE(STATUS "Python libs found in: " ${PYTHON_LIBRARIES} )
ELSE()
  MESSAGE(FATAL_ERROR "Unable to find Python libraries.")
ENDIF()

SET_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

ADD_LIBRARY(pcapreader SHARED ${SOURCE_FILES})
# Libs pthread and dl are prerequisites of SQLiteCpp
TARGET_LINK_LIBRARIES(pcapreader ${TINS_LIBRARY} ${PYTHON_LIBRARIES} SQLiteCpp sqlite3 pthread dl pcap)

ADD_LIBRARY(botnetcomm SHARED ${BOT_COMM_PROC_SOURCE})
TARGET_LINK_LIBRARIES(botnetcomm ${PYTHON_LIBRARIES})

IF (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    ADD_EXECUTABLE(main ${DEBUG_FILES})
    TARGET_LINK_LIBRARIES(main pcapreader ${PYTHON_LIBRARIES})
ENDIF ()

IF (APPLE)
  SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
ENDIF ()

# comment this out to build executable (for development)
#ADD_EXECUTABLE(cpp-pcapreader ${SOURCE_FILES})
#TARGET_LINK_LIBRARIES(cpp-pcapreader "${TINS_LIBRARY}" SQLiteCpp sqlite3 pthread dl)
