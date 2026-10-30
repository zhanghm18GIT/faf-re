# CI-only adapter: same upstream toolchain, temporary assembler alias only.
file(TO_CMAKE_PATH "$ENV{FAF_CI_SOURCE}" _source)
file(TO_CMAKE_PATH "$ENV{FAF_CI_MASM}" _masm)
if(NOT EXISTS "${_source}/cmake/toolchains/clang-cl-x64.cmake" OR NOT EXISTS "${_masm}")
  message(FATAL_ERROR "Reviewed source and assembler paths are required")
endif()
include("${_source}/cmake/toolchains/clang-cl-x64.cmake")
set(CMAKE_ASM_MASM_COMPILER "${_masm}")
