add_executable(demo_zet030 demo_zet030.c)

target_compile_definitions(demo_zet030 PRIVATE ZET030_WITH_TCP=$<BOOL:${ZET030_WITH_TCP}>)
target_compile_definitions(demo_zet030 PRIVATE ZET030_WITH_USB=$<BOOL:${ZET030_WITH_USB}>)

target_include_directories(demo_zet030 PRIVATE ../include)

target_link_libraries(demo_zet030 PRIVATE libzet030 ${LIBUSB_LINK_LIBRARIES})
if(WIN32)
  target_link_libraries(demo_zet030 PRIVATE ws2_32)
else()
  target_link_libraries(demo_zet030 PRIVATE pthread)
endif()

if(MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

if(ZET030_WITH_USB AND VCPKG_INSTALLED_DIR AND EXISTS ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin/${LIBUSB_LIBRARIES}.dll)
  add_custom_command(TARGET demo_zet030 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin/${LIBUSB_LIBRARIES}.dll" "$<TARGET_FILE_DIR:demo_zet030>")
endif()
