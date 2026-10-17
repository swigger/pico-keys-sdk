#ifdef ESP_PLATFORM
#include "pico_random.h"
#include "bootloader_random.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/ctr_drbg.h"
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>

static mbedtls_ctr_drbg_context generator;
static SemaphoreHandle_t random_lock;
static bool seeding;
static unsigned requests;

static int boot_entropy(void *unused, unsigned char *out, size_t length) {
    (void)unused;
    // SAR entropy is only safe before Wi-Fi starts. Never reseed from a sleeping
    // radio or re-enable the SAR source while the radio owns the hardware.
    if (!seeding) return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    esp_fill_random(out, length);
    return 0;
}

void picok_random_init(void) {
    if (random_lock) return; // Boot-task-only initialization; never lazy on workers.
    random_lock = xSemaphoreCreateMutex();
    if (!random_lock) abort();
    mbedtls_ctr_drbg_init(&generator);
    static const unsigned char domain[] = "PicoKeys ESP boot DRBG v1";
    bootloader_random_enable();
    seeding = true;
    int err = mbedtls_ctr_drbg_seed(&generator, boot_entropy, NULL, domain, sizeof(domain) - 1);
    seeding = false;
    bootloader_random_disable();
    if (err) abort();
    // No reseed after boot (see boot_entropy). SP 800-90A allows 2^48 requests;
    // picok_random_fill enforces a much stricter 2^24 and aborts (reboots) beyond it.
    mbedtls_ctr_drbg_set_reseed_interval(&generator, INT_MAX);
}

void picok_random_fill(void *buffer, size_t length) {
    if (!random_lock || (!buffer && length) || xSemaphoreTake(random_lock, portMAX_DELAY) != pdTRUE) abort();
    unsigned char *out = buffer;
    while (length) {
        size_t chunk = length > MBEDTLS_CTR_DRBG_MAX_REQUEST ? MBEDTLS_CTR_DRBG_MAX_REQUEST : length;
        if (requests >= (1u << 24) || mbedtls_ctr_drbg_random(&generator, out, chunk)) abort();
        ++requests;
        out += chunk;
        length -= chunk;
    }
    if (xSemaphoreGive(random_lock) != pdTRUE) abort();
}
#endif
