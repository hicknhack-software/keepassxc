if(WITH_XC_SHARING)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

    set(sharing_SOURCES
	DatabaseSettingsSharingPage.cpp
	DatabaseSettingsSharingWidget.cpp
	Sharing.cpp
	SharingObserver.cpp
	Signature.cpp
	group/GroupSharingWidget.cpp
    )

    add_library(sharing STATIC ${sharing_SOURCES})
    target_link_libraries(sharing Qt5::Core Qt5::Widgets Qt5::Network ${GCRYPT_LIBRARIES} ${QUAZIP_LIBRARIES})
endif()
