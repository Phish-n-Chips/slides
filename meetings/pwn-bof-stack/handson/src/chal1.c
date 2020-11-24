#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "stkdbg.h"
#ifndef NO_DUMP
#define DUMP(X) X
#else
#define DUMP(X)
#endif

void f()
{
  char x[8]   = "AAAAAAAA";
  char buf[8] = "BUFFER  ";
  char z[8]   = "CCCCCCCC";
  DUMP(dump_stack(48));
  read(0, buf, 16);
  DUMP(dump_stack(48));
  write(1, x, 8); write(1, "\n", 1);
  if (memcmp(x, "AAAAAAAA", 8) != 0) {
    puts("You win!");
  }
}

int main()
{
  f();
  return 0;
}
