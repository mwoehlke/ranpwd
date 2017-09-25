cmake_minimum_required(VERSION 3.0)
project(ranpwd LANGUAGES C VERSION 1.3)

include(CheckFunctionExists)
include(CheckIncludeFiles)
include(GNUInstallDirs)

###############################################################################
# Project configuration

set(CMAKE_INCLUDE_CURRENT_DIR ON)

check_include_files("getopt.h" HAVE_GETOPT_H)
if(HAVE_GETOPT_H)
  check_function_exists(getopt_long HAVE_GETOPT_LONG)
endif()

###############################################################################
# Build rules

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_executable(${PROJECT_NAME} ${PROJECT_NAME}.c)

###############################################################################
# Install rules

install(
  TARGETS ${PROJECT_NAME}
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
  FILES ${PROJECT_NAME}.1
  DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)
