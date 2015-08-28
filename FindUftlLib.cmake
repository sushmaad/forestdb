# Locate uftl I/O libraries on a host OS.

IF (UNIX)
    FIND_LIBRARY(UFTL_LIBRARIES
          PATH_SUFFIXES uftl
                 NAMES uftl
                 PATHS
                     /usr/lib/)
ENDIF()

IF (UFTL_LIBRARIES)
    MESSAGE(STATUS "Found uftl libraries in ${UFTL_LIBRARIES}")
    set(UFTL_LIB ${UFTL_LIBRARIES})
ELSE (UFTL_LIBRARIES)
    MESSAGE(STATUS "Can't find uftl libraries")
ENDIF (UFTL_LIBRARIES)

MARK_AS_ADVANCED(UFTL_LIBRARIES)
