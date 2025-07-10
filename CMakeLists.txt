cmake_minimum_required(VERSION 3.10)
project(libzet030 LANGUAGES C)

option(ZET030_WITH_TCP "Build TCP backend" ON)
option(ZET030_WITH_USB "Build USB backend" ON)

set(ZET030_API
  include/zet030.h
)

set(ZET030_SOURCES
  src/zet030_common.h
  src/zet030_common.c
  src/zsp_core.h
  src/zsp_core.c
  src/zsp_osal.h
  src/zsp_spec.h
)

if(ZET030_WITH_TCP)
  list(APPEND ZET030_SOURCES src/zet030_tcp.c)
endif()

if(ZET030_WITH_USB)
  list(APPEND ZET030_SOURCES src/zet030_usb.c)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED IMPORTED_TARGET libusb-1.0)

add_library(libzet030 STATIC ${ZET030_SOURCES} ${ZET030_API})
target_include_directories(libzet030 PRIVATE src include ${LIBUSB_INCLUDE_DIRS})

add_subdirectory(demo)
