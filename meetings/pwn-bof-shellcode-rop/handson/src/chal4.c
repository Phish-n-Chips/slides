#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char binsh[] = "/bin/sh";

void my_system(const char *cmd) {
  system(cmd);
}

void f() {
  char buf[16];
  read(0, buf, 64);
  printf("Hello, %s! Your ID is:\n", buf);
  my_system("id");
}

int main() {
  f();
  return 0;
}
