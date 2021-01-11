#include <stdio.h>
#include <unistd.h>

char buf1[256];

void f() {
  char buf2[64];

  read(0, buf1, 256); // 1st
  puts(buf1);
  read(0, buf2, 256); // 2nd
  puts(buf2);
}

int main() {
  f();
  return 0;
}
