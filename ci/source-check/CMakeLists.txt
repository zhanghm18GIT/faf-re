cmake_minimum_required(VERSION 3.25)
project(FullFloatSourceRegression LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
if(NOT EXISTS "${FORMATTER_CPP}" OR NOT EXISTS "${FAF_DXSDK_DIR}/Include/d3dx9math.h"
   OR NOT EXISTS "${FAF_DXSDK_DIR}/Lib/x64/d3dx9.lib")
  message(FATAL_ERROR "Actual-source regression and reviewed ephemeral DXSDK required")
endif()
add_executable(formatter_policy "${FORMATTER_CPP}")
# Release otherwise defines NDEBUG: never silently turn this assertion test off.
target_compile_options(formatter_policy PRIVATE /W4 /EHsc /UNDEBUG
  "/clang:-idirafter${FAF_DXSDK_DIR}/Include")
target_link_libraries(formatter_policy PRIVATE "${FAF_DXSDK_DIR}/Lib/x64/d3dx9.lib")
enable_testing()
add_test(NAME formatter_policy COMMAND formatter_policy)
