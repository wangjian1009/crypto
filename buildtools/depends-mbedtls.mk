mbedtls_base:=$(call my-dir)/../depends/mbedtls
mbedtls_output:=$(OUTPUT_PATH)/lib/libmbedtls.a
mbedtls_cpp_flags:=-I$(mbedtls_base)/include
mbedtls_c_flags:=-Wno-implicit-function-declaration
mbedtls_src:=$(wildcard $(mbedtls_base)/library/*.c)
$(eval $(call def_library,mbedtls))
