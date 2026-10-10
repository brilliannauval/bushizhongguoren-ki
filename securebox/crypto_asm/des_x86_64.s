	.file	"des_x86_64.c"
	.text
	.p2align 4
	.type	feistel_f, @function
feistel_f:
.LFB2:
	.cfi_startproc
	leaq	E_TABLE(%rip), %rdx
	movq	%rsi, %r9
	movl	%edi, %edi
	xorl	%eax, %eax
	leaq	48(%rdx), %r8
	.p2align 6
	.p2align 4
	.p2align 3
.L2:
	movl	$32, %ecx
	movq	%rdi, %r10
	subb	(%rdx), %cl
	addq	%rax, %rax
	shrq	%cl, %r10
	addq	$1, %rdx
	movq	%r10, %rcx
	andl	$1, %ecx
	orq	%rcx, %rax
	cmpq	%rdx, %r8
	jne	.L2
	xorq	%r9, %rax
	leaq	S_BOXES(%rip), %rcx
	movq	%rax, %r8
	movq	%rax, %rdi
	movq	%rax, %rsi
	shrq	$42, %r8
	shrq	$36, %rdi
	movl	%r8d, %edx
	movl	%r8d, %r9d
	shrw	%r8w
	shrb	$4, %dl
	andl	$1, %r9d
	andl	$15, %r8d
	shrq	$30, %rsi
	andl	$2, %edx
	orl	%r9d, %edx
	movl	%edi, %r9d
	movzbl	%dl, %edx
	andl	$1, %r9d
	sall	$4, %edx
	addl	%r8d, %edx
	movl	%edx, %edx
	movzbl	(%rcx,%rdx), %r8d
	movl	%edi, %edx
	shrw	%di
	shrb	$4, %dl
	andl	$15, %edi
	andl	$2, %edx
	sall	$4, %r8d
	orl	%r9d, %edx
	movl	%esi, %r9d
	movzbl	%dl, %edx
	andl	$1, %r9d
	sall	$4, %edx
	addl	%edi, %edx
	movq	%rax, %rdi
	movl	%edx, %edx
	shrq	$24, %rdi
	movzbl	64(%rcx,%rdx), %edx
	orl	%edx, %r8d
	movl	%esi, %edx
	shrw	%si
	shrb	$4, %dl
	andl	$15, %esi
	sall	$4, %r8d
	andl	$2, %edx
	orl	%r9d, %edx
	movl	%edi, %r9d
	movzbl	%dl, %edx
	sall	$4, %edx
	addl	%esi, %edx
	movq	%rax, %rsi
	movl	%edx, %edx
	movzbl	128(%rcx,%rdx), %edx
	orl	%r8d, %edx
	andl	$1, %r9d
	shrq	$18, %rsi
	sall	$4, %edx
	movl	%edx, %r8d
	movl	%edi, %edx
	shrw	%di
	shrb	$4, %dl
	andl	$15, %edi
	andl	$2, %edx
	orl	%r9d, %edx
	movl	%esi, %r9d
	movzbl	%dl, %edx
	andl	$1, %r9d
	sall	$4, %edx
	addl	%edi, %edx
	movq	%rax, %rdi
	movl	%edx, %edx
	shrq	$12, %rdi
	movzbl	192(%rcx,%rdx), %edx
	orl	%r8d, %edx
	sall	$4, %edx
	movl	%edx, %r8d
	movl	%esi, %edx
	shrw	%si
	shrb	$4, %dl
	andl	$15, %esi
	andl	$2, %edx
	orl	%r9d, %edx
	movzbl	%dl, %edx
	sall	$4, %edx
	addl	%esi, %edx
	movq	%rax, %rsi
	movl	%edx, %edx
	shrq	$6, %rsi
	movzbl	256(%rcx,%rdx), %edx
	orl	%r8d, %edx
	movl	%edi, %r8d
	sall	$4, %edx
	andl	$1, %r8d
	movl	%edx, %r9d
	movl	%edi, %edx
	shrw	%di
	shrb	$4, %dl
	andl	$15, %edi
	andl	$2, %edx
	orl	%r8d, %edx
	movzbl	%dl, %edx
	sall	$4, %edx
	addl	%edi, %edx
	movl	%esi, %edi
	movl	%edx, %edx
	andl	$1, %edi
	movzbl	320(%rcx,%rdx), %r8d
	movl	%esi, %edx
	shrw	%si
	shrb	$4, %dl
	andl	$15, %esi
	andl	$2, %edx
	orl	%r9d, %r8d
	orl	%edi, %edx
	sall	$4, %r8d
	movzbl	%dl, %edx
	sall	$4, %edx
	addl	%esi, %edx
	movl	%eax, %esi
	movl	%edx, %edx
	andl	$1, %esi
	movzbl	384(%rcx,%rdx), %edi
	movl	%eax, %edx
	shrw	%ax
	shrb	$4, %dl
	andl	$15, %eax
	andl	$2, %edx
	orl	%r8d, %edi
	orl	%esi, %edx
	sall	$4, %edi
	movzbl	%dl, %edx
	sall	$4, %edx
	addl	%edx, %eax
	leaq	P_TABLE(%rip), %rdx
	movl	%eax, %eax
	leaq	32(%rdx), %r8
	movzbl	448(%rcx,%rax), %esi
	xorl	%eax, %eax
	orl	%edi, %esi
	.p2align 6
	.p2align 4
	.p2align 3
.L3:
	movl	$32, %ecx
	movq	%rsi, %r11
	subb	(%rdx), %cl
	addq	%rax, %rax
	shrq	%cl, %r11
	addq	$1, %rdx
	movq	%r11, %rcx
	andl	$1, %ecx
	orq	%rcx, %rax
	cmpq	%rdx, %r8
	jne	.L3
	ret
	.cfi_endproc
.LFE2:
	.size	feistel_f, .-feistel_f
	.p2align 4
	.globl	asm_des_key_schedule
	.type	asm_des_key_schedule, @function
asm_des_key_schedule:
.LFB1:
	.cfi_startproc
	subq	$32, %rsp
	.cfi_def_cfa_offset 40
	movzbl	(%rdi), %eax
	movzbl	1(%rdi), %edx
	xorl	%r9d, %r9d
	movq	%r12, 16(%rsp)
	.cfi_offset 12, -24
	movq	%rsi, %r12
	movzbl	7(%rdi), %esi
	salq	$8, %rax
	movq	%rbp, 8(%rsp)
	orq	%rdx, %rax
	movzbl	2(%rdi), %edx
	movq	%r14, 24(%rsp)
	.cfi_offset 6, -32
	.cfi_offset 14, -16
	salq	$8, %rax
	orq	%rdx, %rax
	movzbl	3(%rdi), %edx
	salq	$8, %rax
	orq	%rax, %rdx
	movzbl	4(%rdi), %eax
	salq	$8, %rdx
	orq	%rdx, %rax
	movzbl	5(%rdi), %edx
	salq	$8, %rax
	orq	%rax, %rdx
	movzbl	6(%rdi), %eax
	salq	$8, %rdx
	orq	%rdx, %rax
	salq	$8, %rax
	orq	%rax, %rsi
	leaq	PC1_TABLE(%rip), %rax
	leaq	56(%rax), %r8
	.p2align 5
	.p2align 4
	.p2align 3
.L8:
	movl	$64, %ecx
	movq	%rsi, %rdx
	subb	(%rax), %cl
	addq	%r9, %r9
	shrq	%cl, %rdx
	addq	$1, %rax
	andl	$1, %edx
	orq	%rdx, %r9
	cmpq	%r8, %rax
	jne	.L8
	movq	%r9, %r10
	xorl	%r11d, %r11d
	andl	$268435455, %r9d
	shrq	$28, %r10
	leaq	SHIFT_SCHEDULE(%rip), %rbp
	leaq	48+PC2_TABLE(%rip), %r8
	andl	$268435455, %r10d
	.p2align 4
	.p2align 3
.L10:
	movzbl	0(%rbp,%r11), %eax
	movl	$28, %edx
	movl	%r10d, %esi
	movl	%r9d, %r14d
	subl	%eax, %edx
	movl	%eax, %ecx
	sall	%cl, %esi
	movl	%edx, %ecx
	shrl	%cl, %r10d
	movl	%eax, %ecx
	sall	%cl, %r14d
	movl	%edx, %ecx
	leaq	PC2_TABLE(%rip), %rdx
	orl	%r10d, %esi
	shrl	%cl, %r9d
	movl	%r14d, %eax
	movl	%esi, %r10d
	andl	$268435455, %esi
	orl	%r9d, %eax
	salq	$28, %rsi
	andl	$268435455, %r10d
	movl	%eax, %r9d
	andl	$268435455, %eax
	orq	%rax, %rsi
	andl	$268435455, %r9d
	xorl	%eax, %eax
	.p2align 6
	.p2align 4
	.p2align 3
.L9:
	movl	$56, %ecx
	movq	%rsi, %r14
	subb	(%rdx), %cl
	addq	%rax, %rax
	shrq	%cl, %r14
	addq	$1, %rdx
	movq	%r14, %rcx
	andl	$1, %ecx
	orq	%rcx, %rax
	cmpq	%rdx, %r8
	jne	.L9
	movq	%rax, (%r12,%r11,8)
	addq	$1, %r11
	cmpq	$16, %r11
	jne	.L10
	movq	8(%rsp), %rbp
	movq	16(%rsp), %r12
	movq	24(%rsp), %r14
	addq	$32, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE1:
	.size	asm_des_key_schedule, .-asm_des_key_schedule
	.p2align 4
	.globl	asm_des_encrypt_block
	.type	asm_des_encrypt_block, @function
asm_des_encrypt_block:
.LFB3:
	.cfi_startproc
	pushq	%r14
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
	pushq	%r13
	.cfi_def_cfa_offset 24
	.cfi_offset 13, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset 12, -32
	movq	%rdx, %r12
	pushq	%rbp
	.cfi_def_cfa_offset 40
	.cfi_offset 6, -40
	movq	%rsi, %rbp
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset 3, -48
	movzbl	(%rdi), %eax
	xorl	%ebx, %ebx
	movzbl	1(%rdi), %edx
	movzbl	7(%rdi), %esi
	salq	$8, %rax
	orq	%rdx, %rax
	movzbl	2(%rdi), %edx
	salq	$8, %rax
	orq	%rdx, %rax
	movzbl	3(%rdi), %edx
	salq	$8, %rax
	orq	%rax, %rdx
	movzbl	4(%rdi), %eax
	salq	$8, %rdx
	orq	%rdx, %rax
	movzbl	5(%rdi), %edx
	salq	$8, %rax
	orq	%rax, %rdx
	movzbl	6(%rdi), %eax
	salq	$8, %rdx
	orq	%rdx, %rax
	salq	$8, %rax
	orq	%rax, %rsi
	leaq	IP_TABLE(%rip), %rax
	leaq	64(%rax), %r8
	.p2align 5
	.p2align 4
	.p2align 3
.L16:
	movl	$64, %ecx
	movq	%rsi, %rdx
	subb	(%rax), %cl
	addq	%rbx, %rbx
	shrq	%cl, %rdx
	addq	$1, %rax
	andl	$1, %edx
	orq	%rdx, %rbx
	cmpq	%rax, %r8
	jne	.L16
	movq	(%r12), %rsi
	movl	%ebx, %edi
	call	feistel_f
	movq	%rbx, %rdx
	movq	8(%r12), %rsi
	shrq	$32, %rdx
	xorl	%edx, %eax
	movl	%eax, %edi
	movl	%eax, %r13d
	call	feistel_f
	movq	16(%r12), %rsi
	xorl	%ebx, %eax
	movl	%r13d, %ebx
	movl	%eax, %edi
	movl	%eax, %r14d
	call	feistel_f
	movq	24(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	32(%r12), %rsi
	xorl	%eax, %r14d
	movl	%r14d, %edi
	movl	%r14d, %r13d
	call	feistel_f
	movq	40(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	48(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	56(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	64(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	72(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	80(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	88(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	96(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	104(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	112(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	120(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	leaq	FP_TABLE(%rip), %rsi
	xorl	%r13d, %eax
	leaq	64(%rsi), %r8
	xorl	%edx, %edx
	salq	$32, %rax
	orq	%rbx, %rax
	.p2align 6
	.p2align 4
	.p2align 3
.L17:
	movl	$64, %ecx
	movq	%rax, %rbx
	subb	(%rsi), %cl
	addq	%rdx, %rdx
	shrq	%cl, %rbx
	addq	$1, %rsi
	movq	%rbx, %rcx
	andl	$1, %ecx
	orq	%rcx, %rdx
	cmpq	%rsi, %r8
	jne	.L17
	bswap	%rdx
	movq	%rdx, 0(%rbp)
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r13
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE3:
	.size	asm_des_encrypt_block, .-asm_des_encrypt_block
	.p2align 4
	.globl	asm_des_decrypt_block
	.type	asm_des_decrypt_block, @function
asm_des_decrypt_block:
.LFB4:
	.cfi_startproc
	pushq	%r14
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
	pushq	%r13
	.cfi_def_cfa_offset 24
	.cfi_offset 13, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset 12, -32
	movq	%rdx, %r12
	pushq	%rbp
	.cfi_def_cfa_offset 40
	.cfi_offset 6, -40
	movq	%rsi, %rbp
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset 3, -48
	movzbl	(%rdi), %eax
	xorl	%ebx, %ebx
	movzbl	1(%rdi), %edx
	movzbl	7(%rdi), %esi
	salq	$8, %rax
	orq	%rdx, %rax
	movzbl	2(%rdi), %edx
	salq	$8, %rax
	orq	%rdx, %rax
	movzbl	3(%rdi), %edx
	salq	$8, %rax
	orq	%rax, %rdx
	movzbl	4(%rdi), %eax
	salq	$8, %rdx
	orq	%rdx, %rax
	movzbl	5(%rdi), %edx
	salq	$8, %rax
	orq	%rax, %rdx
	movzbl	6(%rdi), %eax
	salq	$8, %rdx
	orq	%rdx, %rax
	salq	$8, %rax
	orq	%rax, %rsi
	leaq	IP_TABLE(%rip), %rax
	leaq	64(%rax), %r8
	.p2align 5
	.p2align 4
	.p2align 3
.L22:
	movl	$64, %ecx
	movq	%rsi, %rdx
	subb	(%rax), %cl
	addq	%rbx, %rbx
	shrq	%cl, %rdx
	addq	$1, %rax
	andl	$1, %edx
	orq	%rdx, %rbx
	cmpq	%rax, %r8
	jne	.L22
	movq	120(%r12), %rsi
	movl	%ebx, %edi
	call	feistel_f
	movq	%rbx, %rdx
	movq	112(%r12), %rsi
	shrq	$32, %rdx
	xorl	%edx, %eax
	movl	%eax, %edi
	movl	%eax, %r13d
	call	feistel_f
	movq	104(%r12), %rsi
	xorl	%ebx, %eax
	movl	%r13d, %ebx
	movl	%eax, %edi
	movl	%eax, %r14d
	call	feistel_f
	movq	96(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	88(%r12), %rsi
	xorl	%eax, %r14d
	movl	%r14d, %edi
	movl	%r14d, %r13d
	call	feistel_f
	movq	80(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	72(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	64(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	56(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	48(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	40(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	32(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	24(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	16(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	movq	8(%r12), %rsi
	xorl	%eax, %r13d
	movl	%r13d, %edi
	call	feistel_f
	movq	(%r12), %rsi
	xorl	%eax, %ebx
	movl	%ebx, %edi
	call	feistel_f
	leaq	FP_TABLE(%rip), %rsi
	xorl	%r13d, %eax
	leaq	64(%rsi), %r8
	xorl	%edx, %edx
	salq	$32, %rax
	orq	%rbx, %rax
	.p2align 6
	.p2align 4
	.p2align 3
.L23:
	movl	$64, %ecx
	movq	%rax, %rbx
	subb	(%rsi), %cl
	addq	%rdx, %rdx
	shrq	%cl, %rbx
	addq	$1, %rsi
	movq	%rbx, %rcx
	andl	$1, %ecx
	orq	%rcx, %rdx
	cmpq	%rsi, %r8
	jne	.L23
	bswap	%rdx
	movq	%rdx, 0(%rbp)
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r13
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE4:
	.size	asm_des_decrypt_block, .-asm_des_decrypt_block
	.p2align 4
	.globl	asm_des_cbc_crypt
	.type	asm_des_cbc_crypt, @function
asm_des_cbc_crypt:
.LFB5:
	.cfi_startproc
	subq	$264, %rsp
	.cfi_def_cfa_offset 272
	movq	%rbx, 216(%rsp)
	.cfi_offset 3, -56
	movq	%rsi, %rbx
	leaq	64(%rsp), %rsi
	movq	%rbp, 224(%rsp)
	.cfi_offset 6, -48
	movq	%r8, %rbp
	movq	%r15, 256(%rsp)
	.cfi_offset 15, -16
	movq	%rdx, %r15
	movq	%rdi, 8(%rsp)
	movq	%rcx, %rdi
	movq	%r12, 232(%rsp)
	movq	%rdx, 48(%rsp)
	.cfi_offset 12, -40
	movq	%fs:40, %r12
	movq	%r12, 200(%rsp)
	movl	%r9d, %r12d
	call	asm_des_key_schedule@PLT
	movq	0(%rbp), %rax
	testq	%r15, %r15
	je	.L27
	movq	%r14, 248(%rsp)
	testl	%r12d, %r12d
	.cfi_offset 14, -24
	jne	.L39
	movq	8(%rsp), %r12
	movq	48(%rsp), %r14
	xorl	%ebp, %ebp
	.p2align 4
	.p2align 3
.L31:
	movq	(%r12), %xmm0
	movq	%rax, %xmm1
	leaq	(%rbx,%rbp), %rsi
	leaq	64(%rsp), %rdx
	leaq	192(%rsp), %rdi
	addq	$8, %r12
	pxor	%xmm1, %xmm0
	movq	%xmm0, 192(%rsp)
	call	asm_des_encrypt_block@PLT
	movq	(%rbx,%rbp), %rax
	addq	$8, %rbp
	cmpq	%r14, %rbp
	jb	.L31
	movq	248(%rsp), %r14
	.cfi_restore 14
.L27:
	movq	200(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L40
	movq	216(%rsp), %rbx
	movq	224(%rsp), %rbp
	movq	232(%rsp), %r12
	movq	256(%rsp), %r15
	addq	$264, %rsp
	.cfi_def_cfa_offset 8
	ret
.L39:
	.cfi_def_cfa_offset 272
	.cfi_offset 14, -24
	leaq	192(%rsp), %rdx
	movq	%r13, 240(%rsp)
	movq	%rbx, %r8
	xorl	%r9d, %r9d
	movq	%rdx, 56(%rsp)
	.cfi_offset 13, -32
	.p2align 4
	.p2align 3
.L30:
	movzbl	%ah, %ecx
	movq	%rax, 24(%rsp)
	movq	%rax, %r15
	movq	%rax, %r14
	movq	%rax, %r13
	movq	%rax, %r12
	movq	%rax, %rbp
	movq	%rax, %rbx
	movq	8(%rsp), %rax
	movq	56(%rsp), %rsi
	leaq	64(%rsp), %rdx
	movq	%r8, 40(%rsp)
	movb	%cl, 39(%rsp)
	shrq	$16, %r15
	shrq	$24, %r14
	leaq	(%rax,%r9), %rdi
	movq	%r9, 16(%rsp)
	shrq	$32, %r13
	shrq	$40, %r12
	call	asm_des_decrypt_block@PLT
	movq	40(%rsp), %r8
	movq	24(%rsp), %rax
	shrq	$48, %rbp
	xorb	192(%rsp), %al
	movq	16(%rsp), %r9
	shrq	$56, %rbx
	movb	%al, (%r8)
	movq	8(%rsp), %rax
	addq	$8, %r8
	movzbl	39(%rsp), %ecx
	xorb	194(%rsp), %r15b
	xorb	193(%rsp), %cl
	xorb	195(%rsp), %r14b
	movb	%r15b, -6(%r8)
	xorb	196(%rsp), %r13b
	xorb	197(%rsp), %r12b
	movb	%cl, -7(%r8)
	xorb	198(%rsp), %bpl
	xorb	199(%rsp), %bl
	movb	%r14b, -5(%r8)
	movb	%r13b, -4(%r8)
	movb	%r12b, -3(%r8)
	movb	%bpl, -2(%r8)
	movb	%bl, -1(%r8)
	movq	(%rax,%r9), %rax
	addq	$8, %r9
	cmpq	48(%rsp), %r9
	jb	.L30
	movq	240(%rsp), %r13
	.cfi_restore 13
	movq	248(%rsp), %r14
	.cfi_restore 14
	jmp	.L27
.L40:
	movq	%r13, 240(%rsp)
	movq	%r14, 248(%rsp)
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5:
	.size	asm_des_cbc_crypt, .-asm_des_cbc_crypt
	.section	.rodata
	.align 16
	.type	SHIFT_SCHEDULE, @object
	.size	SHIFT_SCHEDULE, 16
SHIFT_SCHEDULE:
		.byte	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
	.align 32
	.type	PC2_TABLE, @object
	.size	PC2_TABLE, 48
PC2_TABLE:
		.byte	14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
	.align 32
	.type	PC1_TABLE, @object
	.size	PC1_TABLE, 56
PC1_TABLE:
		.byte	57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
	.align 32
	.type	S_BOXES, @object
	.size	S_BOXES, 512
S_BOXES:
		.byte	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
		.byte	15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
	.string	"\n"
		.byte	9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
		.byte	7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
		.byte	2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
		.byte	12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
		.byte	4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
		.byte	13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
	.align 32
	.type	P_TABLE, @object
	.size	P_TABLE, 32
P_TABLE:
		.byte	16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
	.align 32
	.type	E_TABLE, @object
	.size	E_TABLE, 48
E_TABLE:
		.byte	32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
	.align 32
	.type	FP_TABLE, @object
	.size	FP_TABLE, 64
FP_TABLE:
		.byte	40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
	.align 32
	.type	IP_TABLE, @object
	.size	IP_TABLE, 64
IP_TABLE:
		.byte	58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
	.ident	"GCC: (GNU) 16.2.1 20260810"
	.section	.note.GNU-stack,"",@progbits
