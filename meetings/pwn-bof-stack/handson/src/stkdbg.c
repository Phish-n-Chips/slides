#include "stkdbg.h"
#include <stdio.h>
#include <ctype.h>

__attribute__((noinline))
void dump_stack(int n) {
  int wordsize = sizeof(void*);
  int i, j;
  const char *fmt = wordsize == 4
    ? " ; %08lx [esp+0x%02x] =>  | %08lx | "
    : " ; %012lx [rsp+0x%02x] =>  | %016lx | ";
  const char *sep = wordsize == 4
    ? " ;                         +----------+%s\n"
    : " ;                             +------------------+%s\n";
  const char *sp = wordsize == 4 ? " <-- esp" : " <-- rsp";
  const char *bp = wordsize == 4 ? " <-- ebp" : " <-- rbp";
  void **p = 0, *p1 = 0, *caller_bp = 0;
  p = (void **)__builtin_frame_address(0);
  p1 = caller_bp = *p;
  p++;
  p1 = (void**)p1 + 1;
  printf(" ; current stack content\n");
  if (wordsize == 4) {
    unsigned char *code = *(unsigned char**)p;
    if (code[0] == 0x83 && code[1] == 0xc4) {
      // add esp, imm
      p += code[2] / wordsize;
    }
  }
  p++;
  for (i = 0; i < n/wordsize; i++) {
    printf(sep, i == 0 ? sp : &p[i] == caller_bp ? bp : "");
    printf(fmt, (unsigned long)&p[i], i*wordsize, (unsigned long)p[i]);
    for (j = 0; j < wordsize; j++) {
      int c = 0xff & (int)((unsigned long)p[i] >> (j*8));
      printf("%c", isprint(c) ? c : '.');
    }
    if (p1 == &p[i]) {
      printf(" (return addr)");
    }
    printf("\n");
  }
  printf(sep, "");
}

__attribute__((noinline))
void dump_return(void) {
  void **p1 = 0;
  p1 = *(void ***)__builtin_frame_address(0) + 1;
  printf(" ; jump to return address %p ...\n", *p1);
}

