#
# Copyright 2019, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the GNU General Public License version 2. Note that NO WARRANTY is provided.
# See "LICENSE_GPLv2.txt" for details.
#
# @TAG(DATA61_GPL)
#
cmake_minimum_required(VERSION 3.7.2)

# set the build platform
set(PLATFORM odroidc2 CACHE STRING "" FORCE)

# build all libs as static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

set(project_dir "${CMAKE_CURRENT_LIST_DIR}")
get_filename_component(resolved_path ${CMAKE_CURRENT_LIST_FILE} REALPATH)
# repo_dir is distinct from project_dir as this file is symlinked.
# project_dir corresponds to the top level project directory, and
# repo_dir is the absolute path after following the symlink.
get_filename_component(repo_dir ${resolved_path} DIRECTORY)

include(${project_dir}/tools/seL4/cmake-tool/helpers/application_settings.cmake)

correct_platform_strings()

include(${project_dir}/kernel/configs/seL4Config.cmake)

function(add_app app)
    set(destination "${CMAKE_BINARY_DIR}/apps/${app}")
    set_property(GLOBAL APPEND PROPERTY apps_property "$<TARGET_FILE:${app}>")
    add_custom_command(
        TARGET ${app} POST_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${app}> ${destination} BYPRODUCTS ${destination}
    )
endfunction()

# set the variables for the AOS platform

# export the generic timer virtual count for delay functions
set(KernelArmExportVCNTUser ON CACHE BOOL "" FORCE)

# export the PMU so the cycle counter can be configured at user level
set(KernelArmExportPMUUser ON CACHE BOOL "" FORCE)

# domains == 1 for AOS
set(KernelNumDomains 1 CACHE STRING "")

# just 1 core
set(KernelMaxNumNodes 1 CACHE STRING "")

# Enable MCS
set(KernelIsMCS ON CACHE BOOL "" FORCE)

# Elfloader settings that correspond to how Data61 sets its boards up.
ApplyData61ElfLoaderSettings(${KernelPlatform} ${KernelSel4Arch})

# turn on all the nice features for debugging
# TODO for benchmarking, you should turn these OFF.
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
set(KernelVerificationBuild OFF CACHE BOOL "" FORCE)
set(KernelIRQReporting OFF CACHE BOOL "" FORCE)
set(KernelPrinting ON CACHE BOOL "" FORCE)
set(KernelDebugBuild ON CACHE BOOL "" FORCE)
set(HardwareDebugAPI ON CACHE BOOL "" FORCE)
set(SosGDBSupport OFF CACHE BOOL "" FORCE) # Enable debugger

# enable our networking libs
set(LibPicotcp ON CACHE BOOL "" FORCE)
set(LibPicotcpBsd ON CACHE BOOL "" FORCE)
set(LibNfs ON CACHE BOOL "" FORCE)


# -- WE WERE TOLD WE COULD ADD ANY EXTRA FLAGS BY A LAB DEMO -- #

add_compile_options(-O3) # Base optimisation flag

# Re-add some flags that are normally included in -O3.
# Provides a slight performance boost but no idea why.
add_compile_options(-fomit-frame-pointer -fprefetch-loop-arrays)

add_compile_options(-funroll-loops) # Loop optimisations
add_compile_options(-ffunction-sections -fdata-sections) # Other performance optimisations
add_compile_options(-fvisibility=hidden) # Potentially reduce export table size

# Extra linker optimizations that also reduce binary/elf size (through things like removing dead code).
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all -Wl,--sort-common -Wl,--as-needed")