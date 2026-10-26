# -----------------------------------------------------------------------------
# rc4_x86_64.s - High-Performance x86_64 Assembly Implementation of RC4
# System V AMD64 ABI:
#   rdi = 1st arg, rsi = 2nd arg, rdx = 3rd arg, rcx = 4th arg, r8 = 5th arg
# -----------------------------------------------------------------------------

.text
.globl asm_rc4_init
.type asm_rc4_init, @function

# void asm_rc4_init(unsigned char *state, const unsigned char *key, int keylen)
# Args:
#   rdi = state (256-byte buffer)
#   rsi = key
#   edx = keylen
asm_rc4_init:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13

    # Step 1: Initialize identity permutation state[i] = i for i = 0..255
    xorl    %eax, %eax
.Linit_loop:
    movb    %al, (%rdi, %rax)
    incl    %eax
    cmpl    $256, %eax
    jne     .Linit_loop

    # Step 2: Key-Scheduling Algorithm (KSA)
    # i in %r8d (0..255), j in %r9d (0..255)
    xorl    %r8d, %r8d         # i = 0
    xorl    %r9d, %r9d         # j = 0

.Lksa_loop:
    # key[i % keylen]
    movl    %r8d, %eax
    xorl    %edx, %edx
    # Preserve keylen (rcx is scratch)
    movl    %ecx, %r10d        # if keylen was in edx, let's load keylen properly
    # Note: caller passed keylen in %edx. Let's move keylen to %r11d
    # To do divide: eax = i, edx = 0, div r11d => remainder in edx
    # We do this cleanly:

    # j = (j + state[i] + key[i % keylen]) & 0xFF
    movzbl  (%rdi, %r8), %r12d # state[i]
    addl    %r12d, %r9d        # j += state[i]

    # i % keylen:
    movl    %r8d, %eax
    xorl    %edx, %edx
    divl    %r13d              # r13d holds keylen
    # remainder in %edx: key[i % keylen]
    movzbl  (%rsi, %rdx), %eax
    addl    %eax, %r9d
    andl    $0xFF, %r9d        # j = j & 0xFF

    # Swap state[i] and state[j]
    movzbl  (%rdi, %r9), %r10d # state[j]
    movb    %r10b, (%rdi, %r8) # state[i] = state[j]
    movb    %r12b, (%rdi, %r9) # state[j] = old state[i]

    incl    %r8d
    cmpl    $256, %r8d
    jne     .Lksa_pre

    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

.Lksa_pre:
    jmp     .Lksa_loop


.globl asm_rc4_init_safe
.type asm_rc4_init_safe, @function
# void asm_rc4_init_safe(unsigned char *state, const unsigned char *key, int keylen)
# rdi = state, rsi = key, edx = keylen
asm_rc4_init_safe:
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14

    movl    %edx, %r13d        # keylen

    # S[i] = i
    xorq    %rax, %rax
.Lsafe_init:
    movb    %al, (%rdi, %rax)
    incq    %rax
    cmpq    $256, %rax
    jne     .Lsafe_init

    # KSA
    xorl    %r8d, %r8d         # i = 0
    xorl    %r9d, %r9d         # j = 0

.Lsafe_ksa:
    movzbl  (%rdi, %r8), %r10d # S[i]
    addl    %r10d, %r9d        # j += S[i]

    # i % keylen
    movl    %r8d, %eax
    xorl    %edx, %edx
    divl    %r13d              # edx = i % keylen
    movzbl  (%rsi, %rdx), %eax # key[i % keylen]
    addl    %eax, %r9d
    andl    $0xFF, %r9d        # j &= 0xFF

    # Swap S[i] and S[j]
    movzbl  (%rdi, %r9), %r11d # S[j]
    movb    %r11b, (%rdi, %r8)
    movb    %r10b, (%rdi, %r9)

    incl    %r8d
    cmpl    $256, %r8d
    jne     .Lsafe_ksa

    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    ret


.globl asm_rc4_crypt
.type asm_rc4_crypt, @function

# void asm_rc4_crypt(unsigned char *state, const unsigned char *in, unsigned char *out, size_t len)
# Args:
#   rdi = state (256-byte array)
#   rsi = in buffer
#   rdx = out buffer
#   rcx = len
asm_rc4_crypt:
    pushq   %rbx
    pushq   %r12
    pushq   %r13

    testq   %rcx, %rcx
    jz      .Lcrypt_done

    xorl    %r8d, %r8d         # i = 0
    xorl    %r9d, %r9d         # j = 0
    xorq    %r10, %r10         # byte counter = 0

.Lcrypt_loop:
    # i = (i + 1) & 0xFF
    incl    %r8d
    andl    $0xFF, %r8d

    # j = (j + state[i]) & 0xFF
    movzbl  (%rdi, %r8), %eax  # S[i]
    addl    %eax, %r9d
    andl    $0xFF, %r9d

    # Swap S[i] and S[j]
    movzbl  (%rdi, %r9), %ebx  # S[j]
    movb    %bl, (%rdi, %r8)   # S[i] = S[j]
    movb    %al, (%rdi, %r9)   # S[j] = old S[i]

    # t = (S[i] + S[j]) & 0xFF
    addl    %ebx, %eax
    andl    $0xFF, %eax
    movzbl  (%rdi, %rax), %r11d # K = S[t]

    # out[n] = in[n] ^ K
    movb    (%rsi, %r10), %r12b
    xorb    %r11b, %r12b
    movb    %r12b, (%rdx, %r10)

    incq    %r10
    cmpq    %rcx, %r10
    jne     .Lcrypt_loop

.Lcrypt_done:
    popq    %r13
    popq    %r12
    popq    %rbx
    ret
