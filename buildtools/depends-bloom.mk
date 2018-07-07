bloom_base:=$(call my-dir)/../depends/libbloom
bloom_output:=$(OUTPUT_PATH)/lib/libbloom.a
bloom_cpp_flags:=-I$(bloom_base) -I$(bloom_base)/murmur2
bloom_c_flags:=-Wno-implicit-function-declaration
bloom_src:=$(wildcard $(bloom_base)/*.c) $(wildcard $(bloom_base)/murmur2/*.c)
$(eval $(call def_library,bloom))
