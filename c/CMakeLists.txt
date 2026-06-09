cmake_minimum_required(VERSION 3.15)

if(NOT DEFINED PROJECT_VERSION)
    set(PROJECT_VERSION "2.0.0")
endif()

project(kyber-pqc VERSION ${PROJECT_VERSION} LANGUAGES C)

set(KYBER_PQC_SOURCES
    src/kyber_pqc.c
    src/kyber_pem.c
    src/secure.c
    vendor/kyber512/kem.c
    vendor/kyber512/indcpa.c
    vendor/kyber512/polyvec.c
    vendor/kyber512/poly.c
    vendor/kyber512/ntt.c
    vendor/kyber512/cbd.c
    vendor/kyber512/reduce.c
    vendor/kyber512/verify.c
    vendor/kyber512/fips202.c
    vendor/kyber512/symmetric-shake.c
    vendor/kyber512/randombytes.c
)

add_library(kyber_pqc ${KYBER_PQC_SOURCES})

target_compile_definitions(kyber_pqc PRIVATE KYBER_K=2)

if(MSVC)
    target_compile_options(kyber_pqc PRIVATE /O2 /W3)
else()
    target_compile_options(kyber_pqc PRIVATE -O3 -Wall -Wextra)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
        target_compile_options(kyber_pqc PRIVATE -mcpu=native)
    endif()
endif()

if(WIN32)
    target_link_libraries(kyber_pqc PRIVATE advapi32)
endif()

target_include_directories(
    kyber_pqc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/vendor/kyber512
)

set_target_properties(kyber_pqc PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

include(GNUInstallDirs)

install(
    TARGETS kyber_pqc
    EXPORT kyber_pqcTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES
        include/kyber_pqc.h
        include/kyber_pem.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT kyber_pqcTargets
    FILE kyber-pqcTargets.cmake
    NAMESPACE kyber-pqc::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kyber-pqc
)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kyber-pqcConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/kyber-pqcConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kyber-pqc
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/kyber-pqcConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/kyber-pqcConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/kyber-pqcConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kyber-pqc
)

add_executable(kyber-pqc tools/kyber-pqc.c)
target_compile_definitions(
    kyber-pqc
    PRIVATE
        KYBER_PQC_VERSION="${PROJECT_VERSION}"
)
target_link_libraries(kyber-pqc PRIVATE kyber_pqc)

install(TARGETS kyber-pqc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
