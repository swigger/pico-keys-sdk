#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Initialize on the boot task, before Wi-Fi or worker tasks start. Failure is fatal.
void picok_random_init(void);
void picok_random_fill(void *buffer, size_t length);
#ifdef __cplusplus
}
#endif
