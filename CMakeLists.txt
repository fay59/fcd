cmake_minimum_required(VERSION 3.2)

project(fcd)

if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	message(SEND_ERROR "clang is required to build")
endif()

set(EXTRA_EMULATOR_FLAGS "" CACHE STRING "additional compilation flags for emulators like -gline-tables-only")
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 14)

find_package(LLVM 3.9 REQUIRED CONFIG)

find_package(PythonLibs 2.7)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} @ ${LLVM_DIR}")
message(STATUS "Found Python ${PYTHONLIBS_VERSION_STRING} @ ${PYTHON_INCLUDE_PATH}")

### emulator ###

file(GLOB_RECURSE emulatorsources ${CMAKE_SOURCE_DIR}/fcd/*.emulator.cpp)

set(INCBIN_TEMPLATE ${CMAKE_SOURCE_DIR}/fcd/cpu/incbin.linux.tpl)
foreach(emulatorsource ${emulatorsources})
	string(REGEX REPLACE ".+/([^/]+).cpp" "\\1" emulatorbasename "${emulatorsource}")
	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${emulatorbasename}.asm"
	                   COMMAND "${CMAKE_CXX_COMPILER}" -c -emit-llvm --std=gnu++14 -O3 ${EXTRA_EMULATOR_FLAGS} "${emulatorsource}" -o "${CMAKE_BINARY_DIR}/${emulatorbasename}.bc"
	                   COMMAND sed -e "s/{CPU}/x86/" ${INCBIN_TEMPLATE} > "${CMAKE_BINARY_DIR}/${emulatorbasename}.asm"
	                   DEPENDS "${emulatorsource}"
	                   IMPLICIT_DEPENDS CXX "${emulatorsource}"
	                   )
	set(emuasms ${emuasms} "${CMAKE_BINARY_DIR}/${emulatorbasename}.asm")
endforeach()
enable_language(ASM)
add_library(emu OBJECT ${emuasms})

### fcd ###
set(subdirs fcd/ fcd/ast fcd/callconv fcd/clang fcd/codegen fcd/cpu fcd/executables fcd/symbols)
if (${PYTHONLIBS_FOUND})
	set(pythonbindingsfile "${CMAKE_CURRENT_BINARY_DIR}/bindings.cpp")
	set(subdirs ${subdirs} fcd/python)
	add_custom_target(createincludeslinks ALL
	                  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/includes"
	                  COMMAND "${CMAKE_COMMAND}" -E create_symlink ${PYTHON_INCLUDE_DIRS} "${CMAKE_BINARY_DIR}/includes/Python")
	add_custom_command(OUTPUT ${pythonbindingsfile}
	                   COMMAND "${CMAKE_C_COMPILER}" -E ${LLVM_DEFINITIONS} -isystem ${LLVM_INCLUDE_DIRS} "${LLVM_INCLUDE_DIRS}/llvm-c/Core.h" | python "${CMAKE_SOURCE_DIR}/fcd/python/bindings.py" > ${pythonbindingsfile})
endif()

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
target_include_directories(fcd SYSTEM PRIVATE ${CMAKE_BINARY_DIR}/includes ${LLVM_INCLUDE_DIRS})
target_compile_options(fcd PRIVATE --system-header-prefix=llvm/ --system-header-prefix=clang/ --system-header-prefix=clang-c/)
target_compile_options(fcd PRIVATE -Wall -Werror=conversion -Wno-error=sign-conversion -Wshadow -Wunreachable-code -Wempty-body -Wconditional-uninitialized -Winvalid-offsetof -Wnewline-eof)
target_compile_options(fcd PRIVATE -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)

llvm_map_components_to_libnames(llvm_libs core analysis instcombine ipo irreader scalaropts transformutils vectorize support)
target_link_libraries(fcd ${llvm_libs} capstone -Wl,--gc-sections)
# Ubuntu does not package ClangConfig
target_link_libraries(fcd "-L${LLVM_LIBRARY_DIR}" -lclang clangIndex clangCodeGen clangFormat clangToolingCore clangRewrite clangFrontend clangDriver clangParse clangSerialization clangSema clangEdit clangAnalysis clangAST clangLex clangBasic LLVMCoverage LLVMCore LLVMOption)

if (${PYTHONLIBS_FOUND})
	set_source_files_properties(${pythonbindingsfile} PROPERTIES COMPILE_FLAGS -w)
	target_link_libraries(fcd ${PYTHON_LIBRARIES})
endif()
