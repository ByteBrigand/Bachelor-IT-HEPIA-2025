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

    {
      char stack_buffer[4];
      memcpy(stack_buffer, buf, len);
    }

    {
      char *heap_buffer = (char *)malloc(4);
      if (!heap_buffer) continue;
      memcpy(heap_buffer, buf, len);
      free(heap_buffer);
    }
  }
  return 0;
}
