cmake_minimum_required(VERSION 3.7.2)

project(console_test_2 C)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -u __vsyscall_ptr")

# list all source files here
add_executable(console_test_2 EXCLUDE_FROM_ALL src/console_test_2.c)
# list libraries to link binary against
target_link_libraries(console_test_2 muslc sel4 sosapi)

# warn about everything
add_compile_options(-Wall -Werror -W -Wextra)

add_app(console_test_2)