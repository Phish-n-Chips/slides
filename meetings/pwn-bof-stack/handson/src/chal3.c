#include <stdio.h>
#include <unistd.h>
#include "stkdbg.h"
#ifndef NO_DUMP
#define DUMP(X) X
#else
#define DUMP(X)
#endif

void f()
{
  int  x  [2] = { 0x1122, 0x3344 };
  char buf[8] = "BUFFER";
  int  z  [2] = { 0x5566, 0x7788 };

  DUMP(dump_stack(48));
  read(0, buf, 16); // should be 8
  DUMP(dump_stack(48));

  if (x[0] == 1231234123) {
    puts("You win!");
  }
}

int main()
{
  f();
  return 0;
}
