##################################
# DEFINITION OF C++ PROJECT
##################################
project(cpp-pcapreader)

# Define CMake settings
cmake_minimum_required(VERSION 3.2)

if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE "Release")
endif()

if(NOT LIBTINS_VERSION)
   set(LIBTINS_VERSION "0")
endif()

if(NOT LIBTINS_PATCH)
   set(LIBTINS_PATCH "0")
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
    message(STATUS "Running Debug configuration.")
elseif (CMAKE_BUILD_TYPE MATCHES Release)
    message(STATUS "Running Release configuration.")
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the library source files
set(SOURCE_FILES cxx/pcap_processor.cpp cxx/pcap_processor.h cxx/statistics.cpp cxx/statistics.h cxx/statistics_db.cpp cxx/statistics_db.h cxx/utilities.h cxx/utilities.cpp)

# Add botnet comm processor source files
set(BOT_COMM_PROC_SOURCE cxx/botnet_comm_processor.h cxx/botnet_comm_processor.cpp)

# Add the debugging source files
if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(DEBUG_FILES cxx/main.cpp cxx/pcap_processor.cpp cxx/pcap_processor.h cxx/statistics.cpp cxx/statistics.h cxx/statistics_db.cpp cxx/statistics_db.h cxx/utilities.h cxx/utilities.cpp)
endif ()

# macOS 10.14 seems to not add "/usr/local/include" as include path by default
include_directories(/usr/local/include)

# Include SQLiteCpp library and build it
option(SQLITECPP_RUN_CPPLINT OFF)
include_directories(SQLiteCpp/include)
add_subdirectory(SQLiteCpp)

# Include pybind11
include_directories(pybind11/include)

# Find libtins library
if(${LIBTINS_VERSION} VERSION_LESS "4.1" OR ${LIBTINS_PATCH} EQUAL 1)
    message(STATUS "Tins will be built from source.")
    set(TINS_LIBRARY tins)
    link_directories(BEFORE libtins/src)
    include_directories(libtins/include)
    add_subdirectory(libtins)
    set_target_properties(${TINS_LIBRARY} PROPERTIES LIBTINS_ENABLE_CXX11 1)
else()
    find_library(TINS_LIBRARY tins)
    if(TINS_LIBRARY)
      message(STATUS "Tins library found in ${TINS_LIBRARY}")
    else()
      message(FATAL_ERROR "Tins library not found.")
    endif()
endif()

find_package(PythonLibs 3.0 REQUIRED)
if(PYTHONLIBS_FOUND)
  include_directories("${PYTHON_INCLUDE_DIRS}")
  message(STATUS "Python includes found in: " ${PYTHON_INCLUDE_DIRS} )
  message(STATUS "Python libs found in: " ${PYTHON_LIBRARIES} )
else()
  message(FATAL_ERROR "Unable to find Python libraries.")
endif()

set_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(pcapreader SHARED ${SOURCE_FILES})
# Libs pthread and dl are prerequisites of SQLiteCpp
target_link_libraries(pcapreader ${TINS_LIBRARY} ${PYTHON_LIBRARIES} SQLiteCpp sqlite3 pthread dl pcap)

add_library(botnetcomm SHARED ${BOT_COMM_PROC_SOURCE})
target_link_libraries(botnetcomm ${PYTHON_LIBRARIES})

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    add_executable(main ${DEBUG_FILES})
    target_link_libraries(main pcapreader ${PYTHON_LIBRARIES})
endif ()

if (APPLE)
  set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif ()

# comment this out to build executable (for development)
#add_executable(cpp-pcapreader ${SOURCE_FILES})
#target_link_libraries(cpp-pcapreader "${TINS_LIBRARY}" SQLiteCpp sqlite3 pthread dl)
