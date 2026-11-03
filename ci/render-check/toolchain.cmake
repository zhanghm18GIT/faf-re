# CI-only adapter: include the pinned upstream toolchain, with a TEMP-only x64 assembler alias.
file(TO_CMAKE_PATH "$ENV{FAF_CI_SOURCE}" _source)
file(TO_CMAKE_PATH "$ENV{FAF_CI_MASM}" _masm)
set(_arch "$ENV{FAF_CI_ARCH}")
if(NOT _arch MATCHES "^(x64|x86)$" OR NOT EXISTS "${_source}/cmake/toolchains/clang-cl-${_arch}.cmake" OR NOT EXISTS "${_masm}")
  message(FATAL_ERROR "Reviewed source, architecture and assembler paths required")
endif()
include("${_source}/cmake/toolchains/clang-cl-${_arch}.cmake")
set(CMAKE_ASM_MASM_COMPILER "${_masm}")
