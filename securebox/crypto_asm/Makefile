CC = gcc
CFLAGS = -shared -fPIC -O2 -maes -msse4.1 \
         -Wall -Wextra \
         -fvisibility=hidden \
         -D_FORTIFY_SOURCE=2 \
         -fstack-protector-strong \
         -Wl,-z,relro,-z,now,-z,noexecstack \
         -Wl,--exclude-libs,ALL \
         -Wl,--strip-debug

EXPECTED_EXPORTS = asm_rc4_init_safe asm_rc4_crypt \
                   asm_aes128_cbc_encrypt asm_aes128_cbc_decrypt \
                   asm_des_cbc_crypt
FORBIDDEN_EXPORTS = asm_rc4_init

all: libcrypto_asm.so verify

libcrypto_asm.so: rc4_x86_64.s aes_ni_x86_64.s des_x86_64.s
	$(CC) $(CFLAGS) -o $@ $^

verify: libcrypto_asm.so
	@echo "=== Checking forbidden symbols are absent ==="
	@for sym in $(FORBIDDEN_EXPORTS); do \
	    if nm -D $< | grep -q " T $${sym}$$"; then \
	        echo "FAIL: forbidden symbol '$${sym}' is exported from $<"; \
	        exit 1; \
	    fi; \
	    echo "PASS: '$${sym}' is NOT in the dynamic symbol table"; \
	done
	@echo "=== Checking required symbols are present ==="
	@for sym in $(EXPECTED_EXPORTS); do \
	    if ! nm -D $< | grep -q " T $${sym}$$"; then \
	        echo "FAIL: required symbol '$${sym}' is missing from $<"; \
	        exit 1; \
	    fi; \
	    echo "PASS: '$${sym}' is in the dynamic symbol table"; \
	done
	@echo "=== All symbol checks passed ==="

clean:
	rm -f libcrypto_asm.so
