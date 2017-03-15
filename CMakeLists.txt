# $Id: CMakeLists.txt 1320 2014-10-26 08:12:52Z justin $

if(LFL_MOBILE)
  return()
endif()

lfl_project(cb)
lfl_add_package(cb SOURCES cb.cpp
                LINK_LIBRARIES ${LFL_APP_LIB} ${LFL_APP_FRAMEWORK} ${LFL_APP_GRAPHICS}
                ${LFL_APP_AUDIO} app_null_camera app_null_matrix app_null_fft
                app_ffmpeg_resampler app_ffmpeg_loader ${LFL_APP_CONVERT}
                app_libpng_png app_libjpeg_jpeg app_null_gif app_null_ogg app_null_css app_null_ttf
                app_null_ssl app_null_js app_null_tu ${LFL_APP_OS})
lfl_post_build_start(cb cb CrystalBawl)
