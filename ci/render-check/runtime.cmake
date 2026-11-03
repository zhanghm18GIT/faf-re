cmake_minimum_required(VERSION 3.25)
if(NOT EXISTS "${SDK_ARCHIVE}" OR NOT IS_DIRECTORY "${DEST}" OR NOT ARCH MATCHES "^(x64|x86)$")
  message(FATAL_ERROR "Archive, isolated destination and architecture required")
endif()
# Extract data only; the installer and its setup program are never executed.
file(ARCHIVE_EXTRACT INPUT "${SDK_ARCHIVE}" DESTINATION "${DEST}" PATTERNS
  "DXSDK/Redist/Jun2010_d3dx9_43_${ARCH}.cab"
  "DXSDK/Redist/Feb2010_X3DAudio_${ARCH}.cab"
  "DXSDK/Redist/Jun2010_D3DCompiler_43_${ARCH}.cab")
