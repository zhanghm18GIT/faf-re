# Supply via CMAKE_PROJECT_TOP_LEVEL_INCLUDES for only the D3D12/x64 job.
# At root directory completion faf_engine exists. Include only target commands;
# CMake forbids creating a subdirectory while deferred calls are running.
set(_faf_warp_fixture_dir "${CMAKE_CURRENT_LIST_DIR}")
cmake_language(EVAL CODE "cmake_language(DEFER CALL include [[${_faf_warp_fixture_dir}/CMakeLists.txt]])")
