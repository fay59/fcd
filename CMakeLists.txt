cmake_minimum_required(VERSION 3.2)

project(fcd)

if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	message(SEND_ERROR "clang is required to build")
endif()

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 14)

find_package(LLVM 3.9 REQUIRED CONFIG)
find_package(PythonLibs 2.7 REQUIRED)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} @ ${LLVM_DIR}")
message(STATUS "Found Python ${PYTHONLIBS_VERSION_STRING} @ ${PYTHON_INCLUDE_PATH}")

### emulator ###

file(GLOB_RECURSE emulatorsources ${CMAKE_SOURCE_DIR}/fcd/*.emulator.cpp)

set(INCBIN_TEMPLATE ${CMAKE_SOURCE_DIR}/fcd/cpu/incbin.${CMAKE_SYSTEM_NAME}.tpl)
foreach(emulatorsource ${emulatorsources})
	string(REGEX REPLACE ".+/([^/]+)\.emulator\.cpp" "\\1" emulator_isa "${emulatorsource}")
	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${emulator_isa}.emulator.s"
	                   COMMAND "${CMAKE_CXX_COMPILER}" -c -emit-llvm --std=gnu++14 -O3 "${emulatorsource}" -o "${CMAKE_BINARY_DIR}/${emulator_isa}.emulator.bc"
	                   COMMAND sed -e "s/{CPU}/${emulator_isa}/" ${INCBIN_TEMPLATE} > "${CMAKE_BINARY_DIR}/${emulator_isa}.emulator.s"
	                   DEPENDS "${emulatorsource}"
	                   IMPLICIT_DEPENDS CXX "${emulatorsource}"
	                   )
	set(emuasms ${emuasms} "${CMAKE_BINARY_DIR}/${emulator_isa}.emulator.s")
endforeach()
enable_language(ASM)
add_library(emu OBJECT ${emuasms})

### fcd ###
set(subdirs fcd/ fcd/ast fcd/callconv fcd/clang fcd/codegen fcd/cpu fcd/executables fcd/symbols)
set(pythonbindingsfile "${CMAKE_CURRENT_BINARY_DIR}/bindings.cpp")
set(subdirs ${subdirs} fcd/python)
add_custom_command(OUTPUT ${pythonbindingsfile}
				   COMMAND "${CMAKE_C_COMPILER}" -E ${LLVM_DEFINITIONS} -isystem ${LLVM_INCLUDE_DIRS} "${LLVM_INCLUDE_DIRS}/llvm-c/Core.h" | python "${CMAKE_SOURCE_DIR}/fcd/python/bindings.py" > ${pythonbindingsfile})

### header search paths file ###
execute_process(COMMAND "${CMAKE_CXX_COMPILER}" -E -x c++ -v /dev/null OUTPUT_VARIABLE dummy ERROR_VARIABLE defaultHeaderSearchPathList)
string(REGEX REPLACE ".*#include <...> search starts here:\n(.+)\nEnd of search list.*" "\\1" defaultHeaderSearchPathList "${defaultHeaderSearchPathList}")
string(REGEX REPLACE " (/[^\n]+)" "\"\\1\"," defaultHeaderSearchPathList "${defaultHeaderSearchPathList}")
set(defaultFrameworkSearchPathList)
configure_file(fcd/systemIncludePath.cpp.tmpl "${CMAKE_CURRENT_BINARY_DIR}/systemIncludePath.cpp")

# collect files
file(GLOB_RECURSE sources fcd/*.cpp)
file(GLOB_RECURSE headers fcd/*.h)

# remove emulators
string(REGEX REPLACE "[^;]+.emulator.cpp;?" "" sources "${sources}")

add_executable(fcd ${sources} ${headers} $<TARGET_OBJECTS:emu> ${pythonbindingsfile} "${CMAKE_CURRENT_BINARY_DIR}/systemIncludePath.cpp")

# NDEBUG must match llvm's build or it will crash
if (${LLVM_ENABLE_ASSERTIONS})
	target_compile_options(fcd PRIVATE -UNDEBUG)
else()
	target_compile_definitions(fcd PRIVATE -DNDEBUG)
endif()

target_compile_definitions(fcd PRIVATE ${LLVM_DEFINITIONS} FCD_DEBUG=1)
target_include_directories(fcd PRIVATE ${subdirs})
target_include_directories(fcd SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS} ${PYTHON_INCLUDE_DIRS})
target_compile_options(fcd PRIVATE --system-header-prefix=llvm/ --system-header-prefix=clang/ --system-header-prefix=clang-c/)
target_compile_options(fcd PRIVATE -Wall -Werror=conversion -Wno-error=sign-conversion -Wshadow -Wunreachable-code -Wempty-body -Wconditional-uninitialized -Winvalid-offsetof -Wnewline-eof)
target_compile_options(fcd PRIVATE -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)

# The Clang cmake config file is broken on binary distributions. We need a way
# to tell if libclang was linked against the LLVM shared library.
execute_process(COMMAND ldd "${LLVM_LIBRARY_DIR}/libclang.so" COMMAND grep -q libLLVM RESULT_VARIABLE linked_to_libllvm)

if (${linked_to_libllvm} EQUAL 0)
	message(STATUS "Link to LLVM shared library.")
	set(llvm_libs -lLLVM-3.9)
else()
	message(STATUS "Link to LLVM static libraries.")
	llvm_map_components_to_libnames(llvm_libs analysis asmparser bitreader codegen core coverage instcombine instrumentation ipo irreader linker mc mcparser object option passes profiledata scalaropts support target transformutils vectorize)
endif()

# Ubuntu does not package ClangConfig
target_link_libraries(fcd "-L${LLVM_LIBRARY_DIR}" clangIndex clangCodeGen clangFormat clangToolingCore clangRewrite clangFrontend clangDriver clangParse clangSerialization clangSema clangEdit clangAnalysis clangAST clangLex clangBasic)
target_link_libraries(fcd ${llvm_libs} capstone clang dl -Wl,--gc-sections)

set_source_files_properties(${pythonbindingsfile} PROPERTIES COMPILE_FLAGS -w)
target_link_libraries(fcd ${PYTHON_LIBRARIES})
