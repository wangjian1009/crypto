crypto_base:=$(call my-dir)/../crypto
crypto_output:=$(OUTPUT_PATH)/lib/libcrypto.a
crypto_cpp_flags:=-I$(crypto_base)/../depends/libsodium/src/libsodium/include \
                  -I$(crypto_base)/../buildtools/include \
                  -I$(crypto_base)/../depends/mbedtls/include \
                  -I$(crypto_base)/../../cpe/include \
                  -I$(crypto_base)/../include
crypto_src:=$(wildcard $(crypto_base)/src/*.c)
$(eval $(call def_library,crypto))

