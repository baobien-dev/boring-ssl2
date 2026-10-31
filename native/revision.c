/* The one symbol of our own: the BoringSSL commit this library was built from, so a process can check what it loaded. */
#if defined(_WIN32)
#define BORING_SSL2_EXPORT __declspec(dllexport)
#else
#define BORING_SSL2_EXPORT __attribute__((visibility("default")))
#endif

BORING_SSL2_EXPORT const char *boring_ssl_source_revision(void) {
  return BORING_SSL_SOURCE_REVISION;
}
