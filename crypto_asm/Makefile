AS = gcc
ASFLAGS = -shared -fPIC -O3 -maes -msse4.1 -Wall

all: libcrypto_asm.so

libcrypto_asm.so: rc4_x86_64.s aes_ni_x86_64.s des_x86_64.s
	$(AS) $(ASFLAGS) -o libcrypto_asm.so rc4_x86_64.s aes_ni_x86_64.s des_x86_64.s

clean:
	rm -f libcrypto_asm.so
