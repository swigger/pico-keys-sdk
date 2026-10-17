/* Read existing ESP storage keys without provisioning or changing any eFuse. */
#ifndef PICO_ESP_OTP_READ_H
#define PICO_ESP_OTP_READ_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Bit 0/1 indicates a present key in KEY3/KEY4. On failure both outputs and
 * the mask are cleared; callers must stop before initializing storage. */
bool pico_esp_read_storage_keys(uint8_t first[32], uint8_t second[32], uint8_t *present);
#ifdef __cplusplus
}
#endif
#endif
