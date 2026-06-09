CC ?= cc
ARCH := $(shell uname -m)
CFLAGS ?= -Wall -Wextra -Wpedantic -O3 -Iinclude -Ivendor/kyber512 -DKYBER_K=2
ifeq ($(ARCH),arm64)
CFLAGS += -mcpu=native
endif
ifeq ($(ARCH),aarch64)
CFLAGS += -mcpu=native
endif
LDFLAGS ?=

VENDOR_DIR := vendor/kyber512
VENDOR_SRCS := \
	$(VENDOR_DIR)/kem.c \
	$(VENDOR_DIR)/indcpa.c \
	$(VENDOR_DIR)/polyvec.c \
	$(VENDOR_DIR)/poly.c \
	$(VENDOR_DIR)/ntt.c \
	$(VENDOR_DIR)/cbd.c \
	$(VENDOR_DIR)/reduce.c \
	$(VENDOR_DIR)/verify.c \
	$(VENDOR_DIR)/fips202.c \
	$(VENDOR_DIR)/symmetric-shake.c \
	$(VENDOR_DIR)/randombytes.c

LIB_SRCS := src/kyber_pqc.c src/kyber_pem.c src/secure.c
LIB_OBJS := $(LIB_SRCS:.c=.o) $(VENDOR_SRCS:.c=.o)

.PHONY: all lib test demo clean

all: lib test demo

lib: build/libkyber_pqc.a

build/libkyber_pqc.a: $(LIB_OBJS)
	mkdir -p build
	$(AR) rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(VENDOR_DIR)/%.o: $(VENDOR_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_kyber: tests/test_kyber.c build/libkyber_pqc.a
	$(CC) $(CFLAGS) tests/test_kyber.c build/libkyber_pqc.a -o $@

tests/test_pem: tests/test_pem.c build/libkyber_pqc.a
	$(CC) $(CFLAGS) tests/test_pem.c build/libkyber_pqc.a -o $@

examples/demo: examples/demo.c build/libkyber_pqc.a
	$(CC) $(CFLAGS) examples/demo.c build/libkyber_pqc.a -o $@

test: lib tests/test_kyber tests/test_pem
	./tests/test_kyber
	./tests/test_pem

demo: examples/demo
	./examples/demo

clean:
	rm -rf build src/*.o $(VENDOR_DIR)/*.o tests/test_kyber tests/test_pem examples/demo
