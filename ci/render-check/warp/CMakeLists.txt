if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR NOT TARGET faf_engine)
  message(FATAL_ERROR "WARP fixture requires Windows x64 and the existing production faf_engine target")
endif()
add_executable(faf_d3d12_warp_regression EXCLUDE_FROM_ALL D3D12WarpRegression.cpp)
target_link_libraries(faf_d3d12_warp_regression PRIVATE faf_engine)
# Production code keeps its normal compile flags and is not instrumented.
# This fixture uses explicit checks rather than NDEBUG-sensitive assertions.
set_target_properties(faf_d3d12_warp_regression PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/warp-regression")
