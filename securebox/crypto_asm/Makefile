CC = gcc
# Fix 4: Additional symbol and compiler hardening flags:
#   -fvisibility=hidden   → only explicitly marked symbols are exported; prevents
#                           asm_rc4_init (and other internal labels) from leaking
#                           into the dynamic symbol table even without .globl.
#   -Wl,--exclude-libs,ALL → strip re-exported symbols from static libs linked in.
#   -D_FORTIFY_SOURCE=2   → enable glibc buffer-overflow detection at runtime.
#   -fstack-protector-strong → add stack canaries to functions with local arrays.
#   -Wl,-z,relro,-z,now   → full RELRO: GOT is read-only after startup.
#   -Wl,-z,noexecstack    → mark the stack non-executable.
#   -Wl,--strip-debug     → omit debug info from the production shared object.
CFLAGS = -shared -fPIC -O2 -maes -msse4.1 \
         -Wall -Wextra \
         -fvisibility=hidden \
         -D_FORTIFY_SOURCE=2 \
         -fstack-protector-strong \
         -Wl,-z,relro,-z,now,-z,noexecstack \
         -Wl,--exclude-libs,ALL \
         -Wl,--strip-debug

all: libcrypto_asm.so

libcrypto_asm.so: rc4_x86_64.s aes_ni_x86_64.s des_x86_64.s
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f libcrypto_asm.so
