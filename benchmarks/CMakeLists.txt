cmake_minimum_required(VERSION 3.15)
project(zeek-benchmarks CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    google_benchmark
    GIT_REPOSITORY https://github.com/CodSpeedHQ/codspeed-cpp
    GIT_TAG v2.1.0
    SOURCE_SUBDIR google_benchmark)

FetchContent_MakeAvailable(google_benchmark)

add_executable(zeek_benchmarks bench.cpp)
target_link_libraries(zeek_benchmarks benchmark::benchmark)
