#if defined(_WIN32)
#define BORING_SSL_EXPORT __declspec(dllexport)
#else
#define BORING_SSL_EXPORT __attribute__((visibility("default")))
#endif

BORING_SSL_EXPORT const char *boring_ssl_source_revision(void) {
  return BORING_SSL_SOURCE_REVISION;
}
