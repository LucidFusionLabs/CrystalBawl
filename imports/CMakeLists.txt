# $Id: CMakeLists.txt 1325 2014-10-29 06:08:31Z justin $

if(LFL_GEOIP)
  if(WIN32)
    #nmake -f Makefile.vc
  else()
    ExternalProject_Add(geoip LOG_CONFIGURE ON LOG_BUILD ON
                        PREFIX ${CMAKE_CURRENT_BINARY_DIR}/geoip-api-c
                        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/geoip-api-c
                        CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>)
    add_library(libGeoIP IMPORTED STATIC GLOBAL)
    add_dependencies(libGeoIP geoip)
    set_property(TARGET libGeoIP PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/geoip-aip-c/libGeoIP/lib/libGeoIP.a)
    set(GEOIP_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/geoip-api-c/libGeoIP/include PARENT_SCOPE)
    set(GEOIP_LIB libGeoIP PARENT_SCOPE)
  endif()
endif()
