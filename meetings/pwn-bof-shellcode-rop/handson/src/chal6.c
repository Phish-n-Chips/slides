#include <stdio.h>
#include <unistd.h>

char buf[1024];
char flag_filename[] = "flag.txt";

void make_cat_command(char *command, char *filename) {
  sprintf(command, "cat %s", filename);
}

void run_shell(char *command) {
  char *cmds[] = {"/bin/sh", "-c", command, 0};
  execve("/bin/sh", cmds, NULL);
}

void vuln() {
  char stkbuf[64];
  read(0, stkbuf, 1024);
}

int main() {
  vuln();
  return 0;
}
