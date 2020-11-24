#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "stkdbg.h"
#ifndef NO_DUMP
#define DUMP(X) X
#else
#define DUMP(X)
#endif

void hint();

void func() {
  char x[8] = "ABCDEFGH";
  char y[8] = "XXXXXXXX";
  char z[8] = "IJKLMNOP";
  DUMP(hint());
  DUMP(dump_stack(64));
  printf("What's your name? > ");
  fflush(stdout);
  scanf("%s", y);
  DUMP(dump_stack(64));
  printf("Hello, %s!\n", y);
  DUMP(dump_return());
  return;
}

int main() {
  func();
  return 0;
}

__attribute__((section(".win")))
void win() {
  puts("Win!!");
  execl("/bin/sh", "/bin/sh", NULL);
}

DUMP(
void hint() {
  printf(" ; Function addresses\n");
  printf(" ;   main: %p\n", main);
  printf(" ;   func: %p\n", func);
  printf(" ;   win:  %p\n", win);
}
)
