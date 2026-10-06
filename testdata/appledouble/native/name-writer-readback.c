/* Read-only native cross-version verification of retained filename images. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void must(int bad, const char *s) {
  if (bad) {
    perror(s);
    exit(2);
  }
}
static void hexname(const char *s) {
  for (size_t i = 0; i < strlen(s); i++)
    printf("%02x", (unsigned char)s[i]);
}
static void unhex(const char *s, char *out) {
  size_t n = strlen(s);
  must(n % 2 || n > 2048, "hex length");
  for (size_t i = 0; i < n; i += 2) {
    unsigned x;
    must(sscanf(s + i, "%2x", &x) != 1 || !x, "hex");
    out[i / 2] = (char)x;
  }
  out[n / 2] = 0;
}
int main(int ac, char **av) {
  if (ac != 3)
    return 2;
  int root = open(av[1], O_RDONLY | O_DIRECTORY);
  must(root < 0, "root");
  int base = openat(root, "collation", O_RDONLY | O_DIRECTORY);
  must(base < 0, "corpus");
  FILE *input = fopen(av[2], "r");
  must(!input, "cases");
  char *line = NULL;
  size_t cap = 0;
  unsigned count = 0;
  printf("{\"cases\":[");
  while (getline(&line, &cap, input) >= 0) {
    line[strcspn(line, "\n")] = 0;
    char *id = strtok(line, "\t"), *a = strtok(NULL, "\t"),
         *b = strtok(NULL, "\t");
    must(!id || !a || !b || strtok(NULL, "\t"), "fields");
    int dir = openat(base, id, O_RDONLY | O_DIRECTORY);
    must(dir < 0, "case root");
    char names[2][1025];
    unhex(a, names[0]);
    unhex(b, names[1]);
    printf("%s{\"id\":\"%s\",\"results\":[", count ? "," : "", id);
    for (int i = 0; i < 2; i++) {
      errno = 0;
      int file = openat(dir, names[i], O_RDONLY);
      int e = file < 0 ? errno : 0;
      struct stat st = {0};
      ssize_t n = -1;
      if (file >= 0) {
        must(fstat(file, &st), "file stat");
        char byte;
        n = read(file, &byte, 1);
        must(n < 0, "read file");
        must(close(file), "close file");
      }
      printf("%s{\"errno\":%d,\"inode\":%llu,\"size\":%lld,\"read\":%lld}",
             i ? "," : "", e, (unsigned long long)st.st_ino,
             (long long)st.st_size, (long long)n);
    }
    printf("],\"stored\":[");
    int duplicate = dup(dir);
    must(duplicate < 0, "duplicate case");
    DIR *stream = fdopendir(duplicate);
    must(!stream, "case enumeration");
    struct dirent *item;
    int stored = 0;
    errno = 0;
    while ((item = readdir(stream))) {
      if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, ".."))
        continue;
      struct stat value;
      must(fstatat(dir, item->d_name, &value, 0), "stored stat");
      printf("%s{\"name\":\"", stored ? "," : "");
      hexname(item->d_name);
      printf("\",\"inode\":%llu}", (unsigned long long)value.st_ino);
      stored++;
      errno = 0;
    }
    must(errno, "read directory");
    must(closedir(stream), "close directory stream");
    printf("]}");
    must(close(dir), "close case");
    count++;
  }
  must(ferror(input), "read cases");
  free(line);
  must(fclose(input), "close cases");
  must(close(base), "close corpus");
  must(close(root), "close root");
  printf("],\"count\":%u}\n", count);
  return 0;
}
