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

all: libcrypto_asm.so verify

libcrypto_asm.so: rc4_x86_64.s aes_ni_x86_64.s des_x86_64.s
	$(CC) $(CFLAGS) -o $@ $^

verify: libcrypto_asm.so
	@actual="$$(nm -D --defined-only $< | awk '$$2 ~ /^[A-Z]$$/ { print $$3 }' | sort)"; \
	expected="$$(printf '%s\n' $(EXPECTED_EXPORTS) | sort)"; \
	if [ "$$actual" != "$$expected" ]; then \
	    echo "FAIL: exported symbol set differs from approved API"; \
	    printf 'Expected:\n%s\nActual:\n%s\n' "$$expected" "$$actual"; \
	    exit 1; \
	fi
	@echo "PASS: dynamic exports match the approved API exactly"

clean:
	rm -f libcrypto_asm.so
