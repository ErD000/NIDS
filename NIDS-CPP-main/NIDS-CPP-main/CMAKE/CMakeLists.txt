cmake_minimum_required(VERSION 3.0)
project(Main)

find_package(wxWidgets REQUIRED COMPONENTS core base)
include(${wxWidgets_USE_FILE})

add_executable(Main app.cpp)
target_link_libraries(Main ${wxWidgets_LIBRARIES})
