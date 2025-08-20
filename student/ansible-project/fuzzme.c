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
    if (len < 8) continue;
    if (buf[0] == 'a' && buf[1] == 'b' && buf[2] == 'c' &&
        buf[3] == 'd' && buf[4] == 'e' && buf[5] == 'f' &&
        buf[6] == 'g' && buf[7] == '!') {
      crash_here("LOW: abcdefg!");
    }
  }
  return 0;
}
