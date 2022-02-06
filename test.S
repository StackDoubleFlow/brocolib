str d8, [sp, #0xffffffffffffffd0]!
str x21, [sp, #0x8]
stp x20, x19, [sp, #0x10]
stp x29, x30, [sp, #0x20]
add x29, sp, #0x20
mov x20, x2
mov x21, x1
orr w1, wzr, #0x1
mov x2, xzr
mov v8.16b, v0.16b
mov x19, x0
bl 0x1d00510
ldr x0, [x19, #0x18]
cbz x0, 0x1181b0c
mov x1, x21
mov x2, xzr
bl 0x26b2e04
ldr x0, [x19, #0x18]
str x20, [x19, #0x28]
cbz x0, 0x1181b0c
mov v0.16b, v8.16b
mov x1, xzr
bl 0x26b2c14
ldr x0, [x19, #0x18]
cbz x0, 0x1181b0c
ldp x29, x30, [sp, #0x20]
ldp x20, x19, [sp, #0x10]
ldr x21, [sp, #0x8]
mov x1, xzr
ldr d8, [sp], #0x30
b 0x26b2e54
bl 0x10e11a8