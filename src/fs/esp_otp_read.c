/* Existing keys remain readable when new eFuse provisioning is disabled.
 * This translation unit deliberately has no write/protect/burn operation. */
#ifdef ESP_PLATFORM
#include "esp_otp_read.h"
#include "esp_efuse.h"
#include "mbedtls/platform_util.h"

static int read_existing(esp_efuse_block_t block, uint8_t key[32]) {
    if (esp_efuse_key_block_unused(block)) return 0;
    /* A read-protected block can read as zero. It is not an absent key, and a
     * block reserved for a hardware peripheral is not an application key. */
    if (esp_efuse_get_key_dis_read(block) ||
        esp_efuse_get_key_purpose(block) != ESP_EFUSE_KEY_PURPOSE_USER) return -1;
    const esp_efuse_desc_t **field = esp_efuse_get_key(block);
    if (!field || esp_efuse_read_field_blob(field, key, 256) != ESP_OK) return -1;
    uint8_t nonzero = 0;
    for (unsigned i = 0; i < 32; ++i) nonzero |= key[i];
    return nonzero ? 1 : -1;
}

bool pico_esp_read_storage_keys(uint8_t first[32], uint8_t second[32], uint8_t *present) {
    *present = 0;
    mbedtls_platform_zeroize(first, 32); mbedtls_platform_zeroize(second, 32);
    int a = read_existing(EFUSE_BLK_KEY3, first), b = read_existing(EFUSE_BLK_KEY4, second);
    if (a < 0 || b < 0) {
        mbedtls_platform_zeroize(first, 32); mbedtls_platform_zeroize(second, 32);
        return false;
    }
    *present = (uint8_t)((a ? 1 : 0) | (b ? 2 : 0));
    return true;
}
#endif
