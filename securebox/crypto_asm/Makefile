CC = gcc
CFLAGS = -shared -fPIC -O2 -maes -msse4.1 -Wall -Wextra -Wl,-z,relro,-z,now,-z,noexecstack

all: libcrypto_asm.so

libcrypto_asm.so: rc4_x86_64.s aes_ni_x86_64.s des_x86_64.s
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f libcrypto_asm.so
