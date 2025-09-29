.global callme
callme:
  cmp   x2, x3
  cset  x12, lt
  and   w11, w12, #0xff
  cmp   w11, #0x0
  csetm x14, ne
  lsr   x13, x14, x4
  sxtb  x0, w13
  ret

