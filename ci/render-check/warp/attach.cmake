# Supply via CMAKE_PROJECT_TOP_LEVEL_INCLUDES for only the descriptor/x64 job.
# Defer addition until the unmodified source has defined faf_engine.
set(_faf_warp_fixture_dir "${CMAKE_CURRENT_LIST_DIR}")
cmake_language(EVAL CODE "cmake_language(DEFER CALL add_subdirectory \"${_faf_warp_fixture_dir}\" \"${CMAKE_BINARY_DIR}/warp-regression\")")
