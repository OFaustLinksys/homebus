cmake_minimum_required(VERSION 2.6)

ADD_DEFINITIONS(-I..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/..)

IF (BUILD_EXAMPLES)
	ADD_EXECUTABLE(server server.c count.c)
	TARGET_LINK_LIBRARIES(server homebus ${ubox_library} ${blob_library} ${json})

	ADD_EXECUTABLE(client client.c count.c)
	TARGET_LINK_LIBRARIES(client homebus ${ubox_library})
ENDIF()
