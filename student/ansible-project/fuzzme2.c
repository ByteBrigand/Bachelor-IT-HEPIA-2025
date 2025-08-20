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

static uint16_t rd16le(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
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

    if (len < 16) continue;
    if (buf[0]=='F' && buf[1]=='U' && buf[2]=='Z' && buf[3]=='Z') {
      uint8_t ver = buf[4];
      if (ver == 1) {
        if (len >= 15 && buf[9]=='A' && buf[10]=='F' && buf[11]=='L' &&
            buf[12]=='+' && buf[13]=='+' && buf[14]=='\n') {
          crash_here("MEDIUM: simple pattern");
        }
      }
    }
  }
  return 0;
}
