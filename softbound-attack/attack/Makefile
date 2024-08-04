

.PHONY: all fully-protected unprotected

all: fully-protected unprotected

SOFTBOUNDCLANG := $(SOFTBOUND_CLANG_INSTALL)/bin/clang -ggdb -L$(SOFTBOUND_LIB_DIR) -L/usr/lib/gcc/x86_64-linux-gnu/8/ -lm -lrt

fully-protected:
	$(SOFTBOUNDCLANG) -fsoftboundcets changeage.c -o changeage-softbound

unprotected:
	$(SOFTBOUNDCLANG) changeage.c -o changeage-native
