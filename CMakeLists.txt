cmake_minimum_required(VERSION 3.2)
project(fcd)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 14)

find_package(LLVM 3.7 REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} @ ${LLVM_DIR}")

### emulator ###

file(GLOB_RECURSE emulatorsources ${CMAKE_SOURCE_DIR}/fcd/*.emulator.cpp)

set(INCBIN_TEMPLATE ${CMAKE_SOURCE_DIR}/fcd/cpu/incbin.linux.tpl)
foreach(emulatorsource ${emulatorsources})
	string(REGEX REPLACE ".+/([^/]+).cpp" "\\1" emulatorbasename "${emulatorsource}")
	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${emulatorbasename}.asm"
	                   COMMAND clang++-${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR} -c -isystem /usr/include/capstone -emit-llvm --std=gnu++14 -O3 "${emulatorsource}" -o "${CMAKE_BINARY_DIR}/${emulatorbasename}.bc"
	                   COMMAND sed -e "s/{CPU}/x86/" ${INCBIN_TEMPLATE} > "${CMAKE_BINARY_DIR}/${emulatorbasename}.asm"
	                   DEPENDS "${emulatorsource}"
	                   IMPLICIT_DEPENDS CXX "${emulatorsource}"
	                   )
	set(emuasms ${emuasms} "${CMAKE_BINARY_DIR}/${emulatorbasename}.asm")
endforeach()
enable_language(ASM)
add_library(emu OBJECT ${emuasms})

### fcd ###
set(subdirs fcd/ fcd/ast fcd/callconv fcd/cpu fcd/executables fcd/llvm-gvn-rewrite fcd/python)

# collect files
file(GLOB_RECURSE sources fcd/*.cpp)
file(GLOB_RECURSE headers fcd/*.h)
# remove emulators
string(REGEX REPLACE "[^;]+.emulator.cpp;?" "" sources "${sources}")

add_executable(fcd ${sources} ${headers} $<TARGET_OBJECTS:emu>)

# NDEBUG must match llvm's build or it will crash
if (${LLVM_ENABLE_ASSERTIONS})
	target_compile_options(fcd PRIVATE -UNDEBUG)
else()
	target_compile_definitions(fcd PRIVATE -DNDEBUG)
endif()

target_compile_definitions(fcd PRIVATE ${LLVM_DEFINITIONS})
target_include_directories(fcd PRIVATE ${subdirs})
target_include_directories(fcd SYSTEM PRIVATE /usr/include/capstone ${CMAKE_BINARY_DIR}/includes ${LLVM_INCLUDE_DIRS})
target_compile_options(fcd PRIVATE -Wall -Werror=conversion -Wno-error=sign-conversion -Wshadow -Wunreachable-code -Wempty-body -Wconditional-uninitialized -Winvalid-offsetof -Wnewline-eof)
target_compile_options(fcd PRIVATE -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)

llvm_map_components_to_libnames(llvm_libs core analysis instcombine ipo irreader scalaropts transformutils vectorize support)
target_link_libraries(fcd ${llvm_libs} python2.7 capstone -Wl,--gc-sections)
