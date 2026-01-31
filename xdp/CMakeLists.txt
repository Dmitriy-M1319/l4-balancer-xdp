cmake_minimum_required(VERSION 3.18)
project(xdp)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
  COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdp.bpf.o
    COMMAND clang -O2 -g -target bpf
            -c ${CMAKE_CURRENT_SOURCE_DIR}/encaper.bpf.c
            -o xdp.bpf.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/encaper.bpf.c ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
)

add_custom_target(xdp ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdp.bpf.o ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)