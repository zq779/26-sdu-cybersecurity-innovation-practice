cmake_minimum_required(VERSION 3.16)
project(fhe_conv_assignment LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_STATIC "Link against static OpenFHE libraries" OFF)

find_package(OpenFHE CONFIG REQUIRED)

message(STATUS "OpenFHE version: ${BASE_OPENFHE_VERSION}")
message(STATUS "OpenFHE include directory: ${OpenFHE_INCLUDE}")
message(STATUS "OpenFHE library directory: ${OpenFHE_LIBDIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS}")

add_executable(fhe_conv
    src/main.cpp
    src/fhe_convolution.cpp
)

target_include_directories(fhe_conv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)

target_link_directories(fhe_conv PRIVATE
    ${OpenFHE_LIBDIR}
    ${OPENMP_LIBRARIES}
)

if(BUILD_STATIC)
    target_link_libraries(fhe_conv PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(fhe_conv PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()

target_compile_options(fhe_conv PRIVATE -Wall -Wextra -Wpedantic)
