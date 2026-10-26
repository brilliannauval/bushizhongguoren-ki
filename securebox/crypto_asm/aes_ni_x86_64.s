# -----------------------------------------------------------------------------
# aes_ni_x86_64.s - Hardware-Accelerated AES-128 CBC Encryption / Decryption
# Uses Intel/AMD AES-NI instructions:
#   aesenc, aesenclast, aesdec, aesdeclast, aeskeygenassist, aesimc
# Pure x86_64 assembly - System V AMD64 ABI compliant
# -----------------------------------------------------------------------------

.text
.globl asm_aes128_key_expansion
.type asm_aes128_key_expansion, @function

# void asm_aes128_key_expansion(const unsigned char *key, unsigned char *enc_keys, unsigned char *dec_keys)
# rdi = key (16 bytes)
# rsi = enc_keys (176 bytes = 11 round keys of 16 bytes)
# rdx = dec_keys (176 bytes = 11 round keys, or NULL if only enc keys needed)
asm_aes128_key_expansion:
    movdqu  (%rdi), %xmm1
    movdqu  %xmm1, (%rsi)

    aeskeygenassist $0x01, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 16(%rsi)

    aeskeygenassist $0x02, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 32(%rsi)

    aeskeygenassist $0x04, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 48(%rsi)

    aeskeygenassist $0x08, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 64(%rsi)

    aeskeygenassist $0x10, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 80(%rsi)

    aeskeygenassist $0x20, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 96(%rsi)

    aeskeygenassist $0x40, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 112(%rsi)

    aeskeygenassist $0x80, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 128(%rsi)

    aeskeygenassist $0x1b, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 144(%rsi)

    aeskeygenassist $0x36, %xmm1, %xmm2
    call    .Laes128_assist
    movdqu  %xmm1, 160(%rsi)

    test    %rdx, %rdx
    jz      .Lkey_exp_ret

    # Inverse round keys for Equivalent Inverse Cipher:
    # Round 10 of enc is Round 0 of dec
    movdqu  160(%rsi), %xmm0
    movdqu  %xmm0, (%rdx)

    # Rounds 9 down to 1 use InvMixColumns (aesimc)
    movdqu  144(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 16(%rdx)

    movdqu  128(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 32(%rdx)

    movdqu  112(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 48(%rdx)

    movdqu  96(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 64(%rdx)

    movdqu  80(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 80(%rdx)

    movdqu  64(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 96(%rdx)

    movdqu  48(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 112(%rdx)

    movdqu  32(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 128(%rdx)

    movdqu  16(%rsi), %xmm0
    aesimc  %xmm0, %xmm0
    movdqu  %xmm0, 144(%rdx)

    # Round 0 of enc is Round 10 of dec
    movdqu  (%rsi), %xmm0
    movdqu  %xmm0, 160(%rdx)

.Lkey_exp_ret:
    ret

.Laes128_assist:
    pshufd  $0xff, %xmm2, %xmm2
    movdqa  %xmm1, %xmm3
    pslldq  $4, %xmm3
    pxor    %xmm3, %xmm1
    pslldq  $4, %xmm3
    pxor    %xmm3, %xmm1
    pslldq  $4, %xmm3
    pxor    %xmm3, %xmm1
    pxor    %xmm2, %xmm1
    ret


# -----------------------------------------------------------------------------
# CBC Mode Encryption (Pure Assembly with Hardware AES-NI)
# -----------------------------------------------------------------------------
.globl asm_aes128_cbc_encrypt
.type asm_aes128_cbc_encrypt, @function
# void asm_aes128_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
#                             const unsigned char *key, const unsigned char *iv)
# rdi = in, rsi = out, rdx = len, rcx = key, r8 = iv
asm_aes128_cbc_encrypt:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $176, %rsp              # 176 bytes for expanded encryption round keys

    movq    %rdi, %r12              # in
    movq    %rsi, %r13              # out
    movq    %rdx, %r14              # len
    movq    %r8,  %r15              # iv

    # Key expansion
    movq    %rcx, %rdi
    movq    %rsp, %rsi
    xorq    %rdx, %rdx
    call    asm_aes128_key_expansion

    # Load initial IV into %xmm4
    movdqu  (%r15), %xmm4

    testq   %r14, %r14
    jz      .Lcbc_enc_done

.Lcbc_enc_loop:
    movdqu  (%r12), %xmm0
    pxor    %xmm4, %xmm0            # CBC XOR with previous ciphertext / IV

    pxor    (%rsp), %xmm0
    aesenc  16(%rsp), %xmm0
    aesenc  32(%rsp), %xmm0
    aesenc  48(%rsp), %xmm0
    aesenc  64(%rsp), %xmm0
    aesenc  80(%rsp), %xmm0
    aesenc  96(%rsp), %xmm0
    aesenc  112(%rsp), %xmm0
    aesenc  128(%rsp), %xmm0
    aesenc  144(%rsp), %xmm0
    aesenclast 160(%rsp), %xmm0

    movdqu  %xmm0, (%r13)
    movdqa  %xmm0, %xmm4            # Next block's IV is this ciphertext

    addq    $16, %r12
    addq    $16, %r13
    subq    $16, %r14
    jnz     .Lcbc_enc_loop

.Lcbc_enc_done:
    addq    $176, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    ret


# -----------------------------------------------------------------------------
# CBC Mode Decryption (Pure Assembly with Hardware AES-NI)
# -----------------------------------------------------------------------------
.globl asm_aes128_cbc_decrypt
.type asm_aes128_cbc_decrypt, @function
# void asm_aes128_cbc_decrypt(const unsigned char *in, unsigned char *out, size_t len,
#                             const unsigned char *key, const unsigned char *iv)
# rdi = in, rsi = out, rdx = len, rcx = key, r8 = iv
asm_aes128_cbc_decrypt:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $352, %rsp              # 352 bytes (176 enc keys + 176 dec keys)

    movq    %rdi, %r12              # in
    movq    %rsi, %r13              # out
    movq    %rdx, %r14              # len
    movq    %r8,  %r15              # iv

    # Key expansion
    movq    %rcx, %rdi
    movq    %rsp, %rsi
    leaq    176(%rsp), %rdx
    call    asm_aes128_key_expansion

    # Load initial IV into %xmm4
    movdqu  (%r15), %xmm4

    testq   %r14, %r14
    jz      .Lcbc_dec_done

.Lcbc_dec_loop:
    movdqu  (%r12), %xmm0
    movdqa  %xmm0, %xmm5            # Save current ciphertext block for next IV

    pxor    176(%rsp), %xmm0
    aesdec  192(%rsp), %xmm0
    aesdec  208(%rsp), %xmm0
    aesdec  224(%rsp), %xmm0
    aesdec  240(%rsp), %xmm0
    aesdec  256(%rsp), %xmm0
    aesdec  272(%rsp), %xmm0
    aesdec  288(%rsp), %xmm0
    aesdec  304(%rsp), %xmm0
    aesdec  320(%rsp), %xmm0
    aesdeclast 336(%rsp), %xmm0

    pxor    %xmm4, %xmm0            # CBC XOR with previous ciphertext / IV
    movdqu  %xmm0, (%r13)
    movdqa  %xmm5, %xmm4            # Update IV to saved ciphertext

    addq    $16, %r12
    addq    $16, %r13
    subq    $16, %r14
    jnz     .Lcbc_dec_loop

.Lcbc_dec_done:
    addq    $352, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    ret


# -----------------------------------------------------------------------------
# Single Block Helpers (Kept for completeness)
# -----------------------------------------------------------------------------
.globl asm_aes128_encrypt_block
.type asm_aes128_encrypt_block, @function
asm_aes128_encrypt_block:
    movdqu  (%rdi), %xmm0
    movdqu  (%rdx), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  16(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  32(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  48(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  64(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  80(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  96(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  112(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  128(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  144(%rdx), %xmm1
    aesenc  %xmm1, %xmm0
    movdqu  160(%rdx), %xmm1
    aesenclast %xmm1, %xmm0
    movdqu  %xmm0, (%rsi)
    ret

.globl asm_aes128_decrypt_block
.type asm_aes128_decrypt_block, @function
asm_aes128_decrypt_block:
    movdqu  (%rdi), %xmm0
    movdqu  (%rdx), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  16(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  32(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  48(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  64(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  80(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  96(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  112(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  128(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  144(%rdx), %xmm1
    aesdec  %xmm1, %xmm0
    movdqu  160(%rdx), %xmm1
    aesdeclast %xmm1, %xmm0
    movdqu  %xmm0, (%rsi)
    ret
