#include <stdio.h>
#include <stdlib.h>
#include "stkdbg.h"
#ifndef NO_DUMP
#define DUMP(X) X
#else
#define DUMP(X)
#endif

void hint();

void dummy() {
  puts("Nope");
  exit(0);
}

__attribute__((section(".win")))
void win() {
  puts("Win!");
  exit(0);
}

struct S {
  char buf_a[8];  // 8 byte buffer
  void (*fun)();  // 8 byte function pointer
  char buf_b[8];  // 8 byte buffer
};

void f() {
  struct S x = { "BUFFER_A", &dummy, "BUFFER_B" };
  DUMP(hint());
  DUMP(dump_stack(64));
  scanf("%s", x.buf_a);
  DUMP(dump_stack(64));
  printf("%s\n", x.buf_a);
  DUMP(printf(" ; calling function %p ...\n", x.fun));
  x.fun();
}

int main(void) {
  f();
  return 0;
}

DUMP(
void hint() {
  printf(" ; Function addresses\n");
  printf(" ;   main:  %p\n", main);
  printf(" ;   f:     %p\n", f);
  printf(" ;   dummy: %p\n", dummy);
  printf(" ;   win:   %p\n", win);
}
)
