#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#pragma clang optimize off
#pragma GCC optimize("O0")
#ifndef __AFL_INIT
#define __AFL_INIT() do {} while (0)
#endif
#ifndef __AFL_LOOP
#define __AFL_LOOP(x) (1)
#endif

static void crash_here(const char *why) {
  fprintf(stderr, "CRASH: %s\n", why);
  fflush(stderr);
  abort();
}

int main(int argc, char **argv) {
  __AFL_INIT();
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  uint8_t buf[512];
  while (__AFL_LOOP(UINT_MAX)) {
    memset(buf, 0, sizeof(buf));
    ssize_t len = read(0, buf, sizeof(buf));
    if (len <= 0) continue;

    if (len < 6) continue;
    size_t off = 0;
    int ok_cmds = 0;
    for (int cmd_idx = 0; cmd_idx < 2; cmd_idx++) {
      if (off + 2 > (size_t)len) break;
      uint8_t cmd = buf[off++];
      uint8_t l = buf[off++];
      if (off + l > (size_t)len) break;
      if (cmd == 0xA1) {
        if (l >= 6 &&
            buf[off+0]=='A' && buf[off+1]=='F' && buf[off+2]=='L' &&
            buf[off+3]=='+' && buf[off+4]=='+' && buf[off+l-1]==0x00) {
          ok_cmds++;
        }
      }
      off += l;
    }
    if (ok_cmds >= 1) {
      crash_here("HARD: stateful trigger");
    }
  }
  return 0;
}
