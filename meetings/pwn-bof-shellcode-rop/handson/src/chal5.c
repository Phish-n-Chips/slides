#include <string.h>
#include <stdio.h>
#include <unistd.h>

char buf[1024];

void read_file(const char *filename,
	       char *buf, int size) {
  FILE *fp = fopen(filename, "r");
  fread(buf, 1, size, fp);
  fclose(fp);
}

void print_data(char *buf) {
  puts(buf);
}

void vuln() {
  char stkbuf[64];
  read(0, buf, 1024);
  memcpy(stkbuf, buf, 1024);
}

int main() {
  vuln();
  return 0;
}
