cmake_minimum_required(VERSION 3.28)
project(boring_ssl2 LANGUAGES C CXX)

# The BoringSSL commit and brotli release the bundled library is built from. Another version is one cache
# variable away: -DBORINGSSL_REVISION=<commit> -DBORINGSSL_ARCHIVE_SHA256=<sha256> builds that download,
# -DBORINGSSL_SOURCE_DIR=<checkout> builds a checkout on disk as it is, and -DBORINGSSL_PATCHES=<directory>
# applies another set of patches to a download.
set(BORINGSSL_REVISION ed9209cff8b5a2fbc6c10050f29b3355048bda85 CACHE STRING "the BoringSSL commit to download")
set(BORINGSSL_ARCHIVE_SHA256 046965cfd80e906a0fdb0226570ecd59432b75e8db82ccd91e93eb169bbd9fe8 CACHE STRING "SHA-256 of that commit's archive")
set(BORINGSSL_SOURCE_DIR "" CACHE PATH "a BoringSSL checkout to build instead of a download")
set(BORINGSSL_PATCHES "${CMAKE_CURRENT_SOURCE_DIR}/patches/boringssl" CACHE PATH "the patches applied to the download, in file name order")
set(BROTLI_VERSION 1.2.1 CACHE STRING "the brotli release to download")
set(BROTLI_ARCHIVE_SHA256 98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f CACHE STRING "SHA-256 of that release's archive")

include(FetchContent)

set(BUILD_SHARED_LIBS OFF)
set(BUILD_TESTING OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BROTLI_BUILD_TOOLS OFF)
set(BROTLI_DISABLE_TESTS ON)
set(BROTLI_BUNDLED_MODE ON)
# BoringSSL marks its functions for export when it is told it builds a shared library
add_compile_definitions(BORINGSSL_SHARED_LIBRARY)
if(WIN32)
  # brotli does the same with these, and without them its functions would be hidden inside the DLL
  add_compile_definitions(BROTLI_SHARED_COMPILATION BROTLICOMMON_SHARED_COMPILATION BROTLIDEC_SHARED_COMPILATION BROTLIENC_SHARED_COMPILATION)
endif()

if(BORINGSSL_SOURCE_DIR)
  FetchContent_Declare(boringssl SOURCE_DIR "${BORINGSSL_SOURCE_DIR}" EXCLUDE_FROM_ALL)
else()
  find_package(Git REQUIRED)
  FetchContent_Declare(
    boringssl
    URL https://github.com/google/boringssl/archive/${BORINGSSL_REVISION}.tar.gz
    URL_HASH SHA256=${BORINGSSL_ARCHIVE_SHA256}
    PATCH_COMMAND ${CMAKE_COMMAND} -DGIT_EXECUTABLE=${GIT_EXECUTABLE} -DPATCHES=${BORINGSSL_PATCHES} -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/apply_patches.cmake
    EXCLUDE_FROM_ALL
  )
endif()
FetchContent_Declare(
  brotli
  URL https://github.com/google/brotli/archive/refs/tags/v${BROTLI_VERSION}.tar.gz
  URL_HASH SHA256=${BROTLI_ARCHIVE_SHA256}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(boringssl brotli)

add_library(boring_ssl2 SHARED native/revision.c)
target_compile_definitions(boring_ssl2 PRIVATE BORING_SSL_SOURCE_REVISION="${BORINGSSL_REVISION}")
target_link_libraries(boring_ssl2 PRIVATE
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,ssl,crypto,brotlienc,brotlidec,brotlicommon>"
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
  # -Bsymbolic keeps BoringSSL calling itself even when an OpenSSL with the same symbol names is loaded in the process;
  # the static C++ runtime keeps the library free of a libstdc++ the host may not have
  target_link_options(boring_ssl2 PRIVATE LINKER:-Bsymbolic -static-libstdc++ -static-libgcc)
endif()

install(TARGETS boring_ssl2
  LIBRARY DESTINATION boring_ssl2
  RUNTIME DESTINATION boring_ssl2
  ARCHIVE DESTINATION import
)
# the licenses of what the library carries go into the package next to it
install(FILES "${boringssl_SOURCE_DIR}/LICENSE" DESTINATION boring_ssl2/licenses RENAME BORINGSSL)
install(FILES "${brotli_SOURCE_DIR}/LICENSE" DESTINATION boring_ssl2/licenses RENAME BROTLI)
