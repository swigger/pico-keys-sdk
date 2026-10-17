#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE)
void remote_presence_init(void);
void remote_presence_service(void);
bool remote_presence_pairing(void);
void remote_presence_context(uint8_t operation, const uint8_t rp_hash[32],
                             const uint8_t client_hash[32], const char *rp, size_t rp_len);
void remote_presence_clear(void);
void remote_presence_begin(void);
void remote_presence_end(void);
bool remote_presence_take(void);
uint16_t remote_presence_get(uint8_t report_id, uint8_t *buffer, uint16_t len);
void remote_presence_set(uint8_t report_id, const uint8_t *buffer, uint16_t len);
#else
static inline void remote_presence_init(void) {}
static inline void remote_presence_service(void) {}
static inline bool remote_presence_pairing(void) {
    return false;
}
static inline void remote_presence_context(uint8_t op, const uint8_t *rp_hash,
                                           const uint8_t *client_hash, const char *rp, size_t len) {
}
static inline void remote_presence_clear(void) {}
static inline void remote_presence_begin(void) {}
static inline void remote_presence_end(void) {}
static inline bool remote_presence_take(void) {
    return false;
}
#endif
