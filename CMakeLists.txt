# $Id: CMakeLists.txt 1320 2014-10-26 08:12:52Z justin $

if(LFL_MOBILE)
  return()
endif()

lfl_set_os_toolkit(CRYSTALBAWL)
lfl_project(CrystalBawl)
add_subdirectory(imports)

lfl_add_package(CrystalBawl SOURCES cb.cpp
                LINK_LIBRARIES ${LFL_APP_LIB} ${CRYSTALBAWL_FRAMEWORK} ${CRYSTALBAWL_GRAPHICS}
                ${LFL_APP_AUDIO} app_null_camera app_null_matrix app_null_fft
                app_ffmpeg_resampler app_ffmpeg_loader ${LFL_APP_CONVERT}
                app_libpng_png app_libjpeg_jpeg app_null_gif app_null_ogg app_null_css app_null_ttf
                app_null_ssl app_null_js app_null_tu app_null_crashreporting
                ${CRYSTALBAWL_TOOLKIT} ${LFL_APP_OS}
                ASSET_FILES ${LFL_APP_ASSET_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/assets/*)
lfl_post_build_start(CrystalBawl)
