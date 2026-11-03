cmake_minimum_required(VERSION 3.25)
if(NOT EXISTS "${SDK_ARCHIVE}" OR NOT IS_DIRECTORY "${DEST}")
  message(FATAL_ERROR "Pinned archive and isolated empty destination required")
endif()
# One data member from the already SHA256-verified Microsoft archive; never run setup.
file(ARCHIVE_EXTRACT INPUT "${SDK_ARCHIVE}" DESTINATION "${DEST}"
  PATTERNS "DXSDK/Redist/Jun2010_d3dx11_43_x64.cab")
