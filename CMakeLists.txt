cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS 
		"-ggdb -Wall -Wextra -pedantic -std=gnu11 -Wno-incompatible-pointer-types -Wno-unused-parameter")
add_definitions(-D_GNU_SOURCE)

execute_process(COMMAND echo ${add_definitions} RESULT_VARIABLE rv)
execute_process(COMMAND pwd RESULT_VARIABLE rv)

set(MODULES_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/lib/vu/modules)
set(VU_HEADERS ${PROJECT_SOURCE_DIR}/include)
set(VU_DYN_SOURCE_PATH ${CMAKE_BINARY_DIR}/umvu_dynsrc)
set(VU_DYN_HEADER_PATH ${CMAKE_BINARY_DIR}/include)
 
set(VU_SYSCALL_DEFS ${VU_DYN_HEADER_PATH}/syscall_defs.h)
set(R_TABLE_H ${VU_DYN_HEADER_PATH}/r_table.h)
set(VU_ARCHTABLE ${VU_DYN_SOURCE_PATH}/arch_table.c)
set(VU_SYSTABLE ${VU_DYN_SOURCE_PATH}/syscall_table.c)
set(VU_DYN_SOURCES ${VU_ARCHTABLE} ${VU_SYSTABLE})

set(VU_DYN_SOURCE_MKDIR mkdir -p ${VU_DYN_SOURCE_PATH})
execute_process(COMMAND ${VU_DYN_SOURCE_MKDIR})

foreach(DYN ${VU_DYN_SOURCES})
	set(VU_DYN_SOURCE_CREATE touch -d 20000101 ${DYN})
	execute_process(COMMAND ${VU_DYN_SOURCE_CREATE})
endforeach(DYN)

add_subdirectory(scripts)
add_subdirectory(umvu)
add_subdirectory(cmd)
add_subdirectory(test_modules)
add_subdirectory(vsn)
