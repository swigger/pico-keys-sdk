#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Derives a purpose-separated 32-byte secret from this device's own key. The
// relay uses it to seal Wi-Fi passwords for host read-back; the key itself never
// leaves the device. False if the device key is unavailable.
bool remote_presence_derive_key(const char *purpose, uint8_t key[32]);

// Development trace hook. Disabled builds incur no calls or storage.
#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE) && defined(ENABLE_RELAY_DIAGNOSTICS)
void remote_device_trace(uint8_t kind, uint8_t code, uint16_t value);
#else
static inline void remote_device_trace(uint8_t kind, uint8_t code, uint16_t value) { (void)kind; (void)code; (void)value; }
#endif

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
bool remote_presence_verify_digest(const uint8_t id[16], const uint8_t digest[32], const uint8_t signature[64]);
// True if any paired controller key verifies the raw r||s signature.
bool remote_presence_verify_any(const uint8_t digest[32], const uint8_t signature[64]);
// Signs with this device's own key (raw r||s). False if the key is unavailable.
bool remote_presence_device_sign(const uint8_t digest[32], uint8_t signature[64]);
// Optional application hooks. SDK defaults preserve existing local-only behavior.
void remote_device_init(void);
void remote_device_service(void);
bool remote_device_setup_active(void);
bool remote_device_local_allowed(void);
uint8_t remote_device_keepalive(void);
uint16_t remote_device_get(uint8_t report_id, uint8_t *buffer, uint16_t len);
void remote_device_set(uint8_t report_id, const uint8_t *buffer, uint16_t len);
int remote_device_cbor(uint8_t command, const uint8_t *data, size_t length,
                       uint8_t *response, size_t capacity, uint16_t *response_length);
#else
static inline void remote_device_init(void) {}
static inline void remote_device_service(void) {}
static inline bool remote_device_local_allowed(void) { return true; }
static inline uint8_t remote_device_keepalive(void) { return 1; }
static inline bool remote_device_setup_active(void) { return false; }
static inline int remote_device_cbor(uint8_t command, const uint8_t *data, size_t length,
                                     uint8_t *response, size_t capacity, uint16_t *response_length) {
    return 0x30;
}
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
