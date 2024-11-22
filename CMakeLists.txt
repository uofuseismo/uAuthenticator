cmake_minimum_required(VERSION 3.24)
project(uAuthenticator VERSION 0.1.0 LANGUAGES CXX)
enable_testing()

option(ENABLE_LDAP "Enable LDAP authentication" ON)

set(BUILD_SHARED_LIBS YES)

include(FetchContent)
include(CheckCXXCompilerFlag)
set(CMAKE_CXX_STANDARD 20) 
set(CMAKE_CXX_STANDARD_REQUIRED ON) 

# Versioning information
configure_file(${CMAKE_SOURCE_DIR}/src/version.hpp.in
               ${CMAKE_SOURCE_DIR}/include/uAuthenticator/version.hpp)


list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(THREADS_PREFER_PTHREAD_FLAG ON) 
#find_package(spdlog REQUIRED)
#find_package(Boost COMPONENTS program_options date_time iostreams system REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost COMPONENTS system REQUIRED)
if (${ENABLE_LDAP})
   find_package(OpenLDAP REQUIRED) 
else()
   find_package(OpenLDAP)
endif()
find_package(OpenSSL COMPONENTS SSL Crypto)
#find_package(jwt-cpp CONFIG REQUIRED)
#find_package(Catch2 3)

FetchContent_Declare(
   Catch2
   GIT_REPOSITORY https://github.com/catchorg/Catch2.git
   GIT_TAG fa43b77429ba76c462b1898d6cd2f2d7a9416b14
   EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

FetchContent_declare(
   jwt-cpp 
   GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
   GIT_TAG 08bcf77a687fb06e34138e9e9fa12a4ecbe12332 # v0.7.0 release
   EXCLUDE_FROM_ALL
)
set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "disable building examples" FORCE)
FetchContent_MakeAvailable(jwt-cpp)


set(HEADER_FILES
    include/uAuthenticator/authenticator.hpp
    include/uAuthenticator/credentials.hpp
    include/uAuthenticator/permissions.hpp
    include/uAuthenticator/version.hpp) 
set(LIBRARY_SRC
    src/authenticator.cpp
    src/credentials.cpp
    src/permissions.cpp
    src/version.cpp)
if (${OpenLDAP_FOUND})
   message("Found openldap")
   set(LIBRARY_SRC ${LIBRARY_SRC} src/ldap.cpp)
   set(HEADER_FILES ${HEADER_FILES} include/uAuthenticator/ldap.hpp)
endif()

add_library(uAuthenticator ${LIBRARY_SRC})
set_target_properties(uAuthenticator PROPERTIES
                      CXX_STANDARD 20
                      CXX_STANDARD_REQUIRED YES
                      CXX_EXTENSIONS NO)
target_link_libraries(uAuthenticator
                      PUBLIC Threads::Threads
                      PRIVATE jwt-cpp::jwt-cpp OpenSSL::SSL OpenSSL::Crypto)
#                      PUBLIC libzmq Threads::Threads
#                      PRIVATE spdlog::spdlog nlohmann_json::nlohmann_json ${SQLite3_LIBRARIES} ${sodium_LIBRARY_RELEASE})
target_include_directories(uAuthenticator
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
                           PRIVATE Boost::asio
                           PUBLIC $<INSTALL_INTERFACE:${CMAKE_SOURCE_DIR}/include/uAuthenticator>)
if (${OpenLDAP_FOUND})
   target_link_libraries(uAuthenticator PRIVATE ${OpenLDAP_LIBRARIES})
   target_include_directories(uAuthenticator
                              PRIVATE $<BUILD_INTERFACE:${OpenLDAP_INCLUDE_DIR}>)
endif()
target_sources(uAuthenticator
               PUBLIC
                 FILE_SET api
                 TYPE HEADERS
                 FILES ${HEADER_FILES})
 
##########################################################################################
#                                         Installation                                   #
##########################################################################################
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
#set(cmakeModulesDir cmake)
set(PROJECT_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
set(PROJECT_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR})
#export(TARGETS uAuthenticator NAMESPACE uAuthenticator:: FILE ${PROJECT_BINARY_DIR}/uAuthenticatorLibraryDepends.cmake)
set(PROJECT_LIBRARIES uAuthenticator::uAuthenticator) 
configure_file(cmake/${PROJECT_NAME}Config.cmake.in ${PROJECT_NAME}Config.cmake @ONLY)
configure_file(cmake/${PROJECT_NAME}ConfigVersion.cmake.in ${PROJECT_NAME}ConfigVersion.cmake @ONLY)
#configure_package_config_file(
#   cmake/${PROJECT_NAME}Config.cmake.in ${PROJECT_NAME}Config.cmake
#   INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
#   PATH_VARS cmakeModulesDir
#   NO_SET_AND_CHECK_MACRO
#   NO_CHECK_REQUIRED_COMPONENTS_MACRO
#)
#write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}${PROJECT_NAME}Config.cmake" VERSION ${PROJECT_VERSION}
#                                 COMPATIBILITY SameMinorVersion)

install(TARGETS uAuthenticator
        EXPORT ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        FILE_SET api
        COMPONENT Runtime)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_BINDIR}/cmake/${PROJECT_NAME}
        COMPONENT ...)

##########################################################################################
#                                     CPACK Packaging                                    #
##########################################################################################
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "UUSS")
set(CPACK_PACKAGE_CONTACT "ben.baker@utah.edu")
set(CPACK_PACKAGE_LICENSE "MIT")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A simple authenticator library for web applications at University of Utah Seismograph Stations")
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})
set(CPACK_VERBATIM_VARIABLES TRUE)
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_COMPONENTS_ALL libraries headers)
if (WIN32)
    set(CPACK_GENERATOR ZIP WIX)
elseif (APPLE)
    set(CPACK_GENERATOR TGZ productbuild)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CPACK_GENERATOR TGZ RPM)
else()
    set(CPACK_GENERATOR TGZ)
endif()
set(CPACK_SOURCE_IGNORE_FILES
  /\\.git/
  \\.swp
  \\.orig
  /CMakeLists\\.txt\\.user
  /private/
)
include(CPack) # Put this last!

