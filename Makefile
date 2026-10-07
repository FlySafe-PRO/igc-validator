CC = gcc
WINDOWS_CC ?= x86_64-w64-mingw32-gcc
WINDOWS_SODIUM ?= vendor/libsodium-win64
CFLAGS ?= -O2 -Wall -Wextra -Werror

.PHONY: all windows clean
all: vali-flysafe

vali-flysafe: validator.c public_key.h Makefile
	$(CC) $(CFLAGS) -o $@ validator.c -lsodium

windows: vali-flysafe.exe

vali-flysafe.exe: validator.c public_key.h Makefile
	$(WINDOWS_CC) $(CFLAGS) -DSODIUM_STATIC -I$(WINDOWS_SODIUM)/include -static -o $@ validator.c $(WINDOWS_SODIUM)/lib/libsodium.a -ladvapi32 -lbcrypt

clean:
	rm -f vali-flysafe vali-flysafe.exe
