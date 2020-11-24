#include <stdio.h>

int main(void) {
  int x[2] = { 0x414243, 0x646566 };
  char s[8] = "Hello";

  printf("%s %d\n", (char*)x, x[0]);
  printf("%s %d\n", s, *(int*)s);
  return 0;
}
