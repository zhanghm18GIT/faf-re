cmake_minimum_required(VERSION 3.25)
if(NOT EXISTS "${SDK_ARCHIVE}" OR NOT IS_DIRECTORY "${DEST}")
  message(FATAL_ERROR "Archive and isolated destination required")
endif()
file(ARCHIVE_EXTRACT INPUT "${SDK_ARCHIVE}" DESTINATION "${DEST}" PATTERNS
  "DXSDK/Redist/Jun2010_d3dx9_43_x64.cab"
  "DXSDK/Redist/Feb2010_X3DAudio_x64.cab"
  "DXSDK/Redist/Jun2010_D3DCompiler_43_x64.cab")
