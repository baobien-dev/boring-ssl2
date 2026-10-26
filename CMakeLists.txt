cmake_minimum_required(VERSION 3.28)
project(boring_ssl2 LANGUAGES C CXX)

set(BORINGSSL_REVISION 8f77af2e983b73df4f018e2a141450d005f5587b)
set(BORINGSSL_ARCHIVE_SHA256 af937f7eaa814083130d5f0881f5ddad9c7b8a2f024e19d3431941f5cb75442e)
set(BROTLI_VERSION 1.2.0)
set(BROTLI_ARCHIVE_SHA256 816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec)

include(FetchContent)
find_package(Git REQUIRED)

set(BUILD_SHARED_LIBS OFF)
set(BUILD_TESTING OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BROTLI_BUILD_TOOLS OFF)
set(BROTLI_DISABLE_TESTS ON)
set(BROTLI_BUNDLED_MODE ON)
add_compile_definitions(BORINGSSL_SHARED_LIBRARY)

FetchContent_Declare(
  boringssl
  URL https://github.com/google/boringssl/archive/${BORINGSSL_REVISION}.tar.gz
  URL_HASH SHA256=${BORINGSSL_ARCHIVE_SHA256}
  PATCH_COMMAND ${GIT_EXECUTABLE} apply ${CMAKE_CURRENT_SOURCE_DIR}/patches/boringssl/0001-client-hello-extension-order.patch
  EXCLUDE_FROM_ALL
)
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
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # -Bsymbolic keeps BoringSSL calling itself even when an OpenSSL with the same symbol names is loaded in the process
  target_link_options(boring_ssl2 PRIVATE LINKER:-Bsymbolic -static-libstdc++ -static-libgcc)
endif()

install(TARGETS boring_ssl2 LIBRARY DESTINATION boring_ssl2 RUNTIME DESTINATION boring_ssl2)
