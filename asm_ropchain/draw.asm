org 0xE9E0

call 0x0
call 0x1302E
call 0x1E3D0
call 0xDA30
call 0x3030
hex 30 30 7a 01
render.ddd4
er0 = hex a2 d5
getscancode
qr0 = hex 10 30 30 30 30 30 01 30
BL strcpy
call 0x10E80
hex 30 d5 30 30 30 30
call 0x9950
hex 30 30
er2 += er8,rt
er8 = hex 0e d6
xr8 = hex 6c d6 30 30
xr8 = hex 98 d6 30 30
xr8 = hex 30 30 30 30
er0 = hex 90 da
er0 - er2_gt,r0 = 0|r0 = 1,rt
er2 = hex 5e 30
er4 = hex 08 d6
er0 *= r2,er2 = er0,er0 += er4,rt
qr8 = hex 30 30 30 30 30 30 30 30
sp = er6,pop er8
hex 80 eb 74 89
call 0x3031
er0 = hex 76 d5
er0 = hex 02 00
xr8 = hex 30 30 30 30
call 0xD04A
hex 30 30
qr8 = hex 54 d6 30 30 30 30 30 30
xr0 = hex 30 30 31 30
er4 = hex 78 d5
xr8 = hex 30 30 30 30
er2 = hex e2 e9
call 0x28932
hex 01 00 78 5c
call 0x23030
er12 = hex 76 d5
draw_glyph
er2 = hex 30 30
er0 = hex 30 db
er0 - er2_gt,r0 = 0|r0 = 1,rt
er2 = hex 3c 30
er4 = hex 98 d6
er0 *= r2,er2 = er0,er0 += er4,rt
qr8 = hex 30 30 30 30 30 30 30 30
sp = er6,pop er8
hex 30 30 74 89
call 0x3031
xr8 = hex 80 eb 30 30
xr8 = hex cc d6 30 30
qr0 = hex 30 30 31 30 78 d5 90 d5
xr8 = hex 30 30 30 30
er2 = hex e2 e9
hex 32 89 3a 00
hex 30 30 74 1f
call 0x23032
xr0 = hex d4 dd 00 06
memzero
render.ddd4
qr0 = hex 30 30 31 30 78 d5 90 d5
xr8 = hex 30 30 30 30
er2 = hex e2 e9
hex 32 89 08 00
hex 30 30 74 1f
call 0x3032
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
call 0x0
hex 00 00
