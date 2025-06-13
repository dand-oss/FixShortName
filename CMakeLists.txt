cmake_minimum_required(VERSION 3.27)
project(FixShortName LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add _d to debug targets
set(CMAKE_DEBUG_POSTFIX _d)

# Define executable
set(exename "FixShortName")
add_executable(${exename})

# Sources
target_sources(${exename} PRIVATE
    FixShortName.cpp
)

# Link Windows libraries
target_link_libraries(${exename} PRIVATE kernel32)

# Copy executables to install directory
install(TARGETS ${exename} RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)