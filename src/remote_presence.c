#include "remote_presence.h"
#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE)
#include <string.h>
#include "pico_keys.h"
#include "usb.h"
#include "pico_random.h"
#include "driver/gpio.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/platform_util.h"

#define AUTH_WINDOW_MS 90000u
#define PAIR_WINDOW_MS 120000u
#define KEY_SLOTS 4
static portMUX_TYPE state_lock = portMUX_INITIALIZER_UNLOCKED;
static nvs_handle_t storage;
static bool storage_ready;
static uint8_t keys[KEY_SLOTS][65], ids[KEY_SLOTS][16];
// This device's own P-256 key. Generated on the device the first time and never
// exported; pairing hands the public half to the controller. The relay proves
// the device to the safe end with it.
static uint8_t device_secret[32], device_pub[65];
static bool device_ready;
__attribute__((weak)) void remote_device_init(void) {}
__attribute__((weak)) void remote_device_service(void) {}
__attribute__((weak)) bool remote_device_setup_active(void) { return false; }
__attribute__((weak)) bool remote_device_local_allowed(void) { return true; }
__attribute__((weak)) uint8_t remote_device_keepalive(void) { return 1; }
__attribute__((weak)) uint16_t remote_device_get(uint8_t report, uint8_t *b, uint16_t len) { return 0; }
__attribute__((weak)) void remote_device_set(uint8_t report, const uint8_t *b, uint16_t len) {}
__attribute__((weak)) int remote_device_cbor(uint8_t cmd, const uint8_t *data, size_t length,
                                            uint8_t *response, size_t capacity, uint16_t *response_length) {
    return 0x30;
}
static struct {
    bool valid, pending, approved, have_r, candidate, selected;
    uint8_t operation, result, attempts;
    uint32_t generation, started;
    uint8_t nonce[32], rp_hash[32], client_hash[32], signature[64], pub[65], id[16];
    char rp[256];
} state;
// Pair phases: idle, validate, release, press, hold, release-to-save, save,
// done, error, canceled, expired. Only the raw GPIO path can reach save.
static struct {
    uint8_t phase, result, action, staged;
    uint32_t started, pressed;
    uint8_t tx[16], pub[65], id[16];
} pairing;
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void write32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}
static bool live(void) {
    return state.pending && board_millis() - state.started < AUTH_WINDOW_MS;
}
static bool pair_active(void) {
    return pairing.phase >= 1 && pairing.phase <= 6;
}
bool remote_presence_pairing(void) {
    portENTER_CRITICAL(&state_lock);
    bool active = pair_active();
    portEXIT_CRITICAL(&state_lock);
    return active;
}
static int find_id(const uint8_t id[16]) {
    for (int i = 0; i < KEY_SLOTS; i++)
        if (keys[i][0] && !memcmp(ids[i], id, 16))
            return i;
    return -1;
}
static bool valid_pub(const uint8_t pub[65]) {
    mbedtls_ecp_group g;
    mbedtls_ecp_point q;
    mbedtls_ecp_group_init(&g);
    mbedtls_ecp_point_init(&q);
    int r = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
    if (!r)
        r = mbedtls_ecp_point_read_binary(&g, &q, pub, 65);
    if (!r)
        r = mbedtls_ecp_check_pubkey(&g, &q);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&g);
    return !r;
}
static int device_rng(void *ctx, unsigned char *out, size_t length) {
    (void)ctx;
    picok_random_fill(out, length);
    return 0;
}
static bool device_public(const uint8_t secret[32], uint8_t pub[65]) {
    mbedtls_ecp_keypair k;
    mbedtls_ecp_keypair_init(&k);
    size_t n = 0;
    int r = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &k, secret, 32);
    if (!r)
        r = mbedtls_ecp_mul(&k.MBEDTLS_PRIVATE(grp), &k.MBEDTLS_PRIVATE(Q), &k.MBEDTLS_PRIVATE(d),
                            &k.MBEDTLS_PRIVATE(grp).G, device_rng, NULL);
    if (!r)
        r = mbedtls_ecp_point_write_binary(&k.MBEDTLS_PRIVATE(grp), &k.MBEDTLS_PRIVATE(Q),
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &n, pub, 65);
    mbedtls_ecp_keypair_free(&k);
    return !r && n == 65;
}
static void device_key_init(void) {
    uint8_t secret[32];
    size_t n = sizeof(secret);
    esp_err_t err = nvs_get_blob(storage, "device_key", secret, &n);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        mbedtls_ecp_keypair k;
        mbedtls_ecp_keypair_init(&k);
        int r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &k, device_rng, NULL);
        if (!r)
            r = mbedtls_mpi_write_binary(&k.MBEDTLS_PRIVATE(d), secret, 32);
        mbedtls_ecp_keypair_free(&k);
        err = r ? ESP_FAIL : nvs_set_blob(storage, "device_key", secret, 32);
        if (err == ESP_OK)
            err = nvs_commit(storage);
        n = 32;
    }
    if (err == ESP_OK && n == 32 && device_public(secret, device_pub)) {
        memcpy(device_secret, secret, 32);
        device_ready = true;
    }
    mbedtls_platform_zeroize(secret, sizeof(secret));
}
bool remote_presence_device_sign(const uint8_t digest[32], uint8_t signature[64]) {
    if (!device_ready)
        return false;
    mbedtls_ecp_group g;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&g);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    int result = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
    if (!result) result = mbedtls_mpi_read_binary(&d, device_secret, 32);
    if (!result) result = mbedtls_ecdsa_sign(&g, &r, &s, &d, digest, 32, device_rng, NULL);
    if (!result) result = mbedtls_mpi_write_binary(&r, signature, 32);
    if (!result) result = mbedtls_mpi_write_binary(&s, signature + 32, 32);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&g);
    if (result)
        memset(signature, 0, 64);
    return !result;
}
void remote_presence_init(void) {
    // Never erase NVS automatically: it may contain another application's data.
    if (nvs_flash_init() != ESP_OK ||
        nvs_open("remote_presence", NVS_READWRITE, &storage) != ESP_OK)
        return;
    device_key_init();
    uint8_t loaded[KEY_SLOTS][65] = {0};
    size_t n = sizeof(loaded);
    esp_err_t err = nvs_get_blob(storage, "keys_v2", loaded, &n);
    if (err != ESP_ERR_NVS_NOT_FOUND && (err != ESP_OK || n != sizeof(loaded)))
        return;
    if (err == ESP_OK) {
        for (int i = 0; i < KEY_SLOTS; i++) {
            if (loaded[i][0] && !valid_pub(loaded[i]))
                return;
        }
        memcpy(keys, loaded, sizeof(keys));
        for (int i = 0; i < KEY_SLOTS; i++)
            if (keys[i][0]) {
                uint8_t hash[32];
                mbedtls_sha256(keys[i], 65, hash, 0);
                memcpy(ids[i], hash, 16);
            }
    }
    storage_ready = true;
}
void remote_presence_service(void) {
    remote_device_service();
    uint8_t phase, pub[65], action, id[16], tx[16];
    bool busy = is_busy() || remote_device_setup_active();
    bool pressed = gpio_get_level(GPIO_NUM_0) == 0;
    uint32_t now = board_millis();
    portENTER_CRITICAL(&state_lock);
    if (pair_active() && (busy || state.pending)) {
        pairing.phase = 9;
        pairing.result = 3;
    }
    if (pair_active() && now - pairing.started >= PAIR_WINDOW_MS) {
        pairing.phase = 10;
        pairing.result = 6;
    }
    phase = pairing.phase;
    action = pairing.action;
    memcpy(pub, pairing.pub, 65);
    memcpy(id, pairing.id, 16);
    memcpy(tx, pairing.tx, 16);
    portEXIT_CRITICAL(&state_lock);
    if (phase == 1) {
        bool ok = action == 2 || valid_pub(pub);
        uint8_t hash[32] = {0};
        if (action == 1 && ok)
            mbedtls_sha256(pub, 65, hash, 0);
        portENTER_CRITICAL(&state_lock);
        if (pairing.phase == 1 && !memcmp(tx, pairing.tx, 16)) {
            if (action == 1)
                memcpy(pairing.id, hash, 16);
            int slot = find_id(pairing.id);
            bool room = slot >= 0;
            for (int i = 0; i < KEY_SLOTS; i++)
                if (!keys[i][0])
                    room = true;
            if (!ok || !storage_ready || !device_ready || (action == 1 && !room) || (action == 2 && slot < 0)) {
                pairing.phase = 8;
                pairing.result = !ok ? 2 : !storage_ready || !device_ready ? 5 : action == 2 ? 2 : 4;
            } else
                pairing.phase = 2;
        }
        portEXIT_CRITICAL(&state_lock);
        return;
    }
    portENTER_CRITICAL(&state_lock);
    if (pairing.phase == phase && !memcmp(tx, pairing.tx, 16)) {
        if (phase == 2 && !pressed)
            pairing.phase = 3;
        else if (phase == 3 && pressed) {
            pairing.phase = 4;
            pairing.pressed = now;
        } else if (phase == 4) {
            if (!pressed)
                pairing.phase = 3;
            else if (now - pairing.pressed >= 1000)
                pairing.phase = 5;
        } else if (phase == 5 && !pressed)
            pairing.phase = 6;
    }
    phase = !memcmp(tx, pairing.tx, 16) ? pairing.phase : 0;
    portEXIT_CRITICAL(&state_lock);
    if (phase == 6) {
        uint8_t next[KEY_SLOTS][65];
        memcpy(next, keys, sizeof(next));
        int slot = find_id(id);
        if (action == 1 && slot < 0)
            for (int i = 0; i < KEY_SLOTS; i++)
                if (!next[i][0]) {
                    slot = i;
                    break;
                }
        if (slot < 0)
            return;
        if (action == 1)
            memcpy(next[slot], pub, 65);
        else
            memset(next[slot], 0, 65);
        esp_err_t err = nvs_set_blob(storage, "keys_v2", next, sizeof(next));
        if (err == ESP_OK)
            err = nvs_commit(storage);
        portENTER_CRITICAL(&state_lock);
        if (err == ESP_OK) {
            memcpy(keys, next, sizeof(keys));
            if (action == 1)
                memcpy(ids[slot], id, 16);
            else
                memset(ids[slot], 0, 16);
            pairing.phase = 7;
            pairing.result = 1;
        } else {
            pairing.phase = 8;
            pairing.result = 5;
        }
        portEXIT_CRITICAL(&state_lock);
    }
}
void remote_presence_clear(void) {
    portENTER_CRITICAL(&state_lock);
    state.valid = state.pending = state.approved = state.have_r = state.candidate = state.selected =
        false;
    memset(state.nonce, 0, 32);
    memset(state.signature, 0, 64);
    portEXIT_CRITICAL(&state_lock);
}
void remote_presence_context(uint8_t op, const uint8_t rp_hash[32], const uint8_t client_hash[32],
                             const char *rp, size_t len) {
    remote_presence_clear();
    if ((op != 1 && op != 2) || !rp || !len || len > 253)
        return;
    portENTER_CRITICAL(&state_lock);
    if (pair_active()) {
        pairing.phase = 9;
        pairing.result = 3;
    }
    state.operation = op;
    memcpy(state.rp_hash, rp_hash, 32);
    memcpy(state.client_hash, client_hash, 32);
    memset(state.rp, 0, sizeof(state.rp));
    memcpy(state.rp, rp, len);
    state.valid = true;
    portEXIT_CRITICAL(&state_lock);
}
void remote_presence_begin(void) {
    uint8_t nonce[32];
    picok_random_fill(nonce, 32);
    portENTER_CRITICAL(&state_lock);
    if (pair_active()) {
        pairing.phase = 9;
        pairing.result = 3;
    }
    if (state.valid) {
        state.generation++;
        memcpy(state.nonce, nonce, 32);
        state.started = board_millis();
        state.result = state.attempts = 0;
        state.pending = true;
        state.approved = state.have_r = state.candidate = state.selected = false;
    }
    portEXIT_CRITICAL(&state_lock);
}
void remote_presence_end(void) {
    portENTER_CRITICAL(&state_lock);
    state.pending = state.approved = state.have_r = state.candidate = state.selected = false;
    memset(state.nonce, 0, 32);
    memset(state.signature, 0, 64);
    portEXIT_CRITICAL(&state_lock);
}
static void request_digest(uint8_t op, uint32_t gen, const uint8_t nonce[32],
                           const uint8_t context[64], const uint8_t id[16], uint8_t digest[32]) {
    static const char domain[] = "pico-fido2 remote presence v2";
    uint8_t message[sizeof(domain) + 16 + 16 + 1 + 4 + 32 + 64];
    uint8_t *p = message;
    memcpy(p, domain, sizeof(domain));
    p += sizeof(domain);
    memcpy(p, id, 16);
    p += 16;
    memcpy(p, pico_serial_str, 16);
    p += 16;
    *p++ = op;
    write32(p, gen);
    p += 4;
    memcpy(p, nonce, 32);
    p += 32;
    memcpy(p, context, 64);
    mbedtls_sha256(message, sizeof(message), digest, 0);
}
bool remote_presence_take(void) {
    uint8_t sig[64], nonce[32], context[64], pub[65], id[16], op = 0;
    uint32_t gen = 0;
    bool verify = false;
    portENTER_CRITICAL(&state_lock);
    if (live() && state.candidate && state.selected && state.attempts < 5) {
        state.candidate = false;
        state.attempts++;
        gen = state.generation;
        op = state.operation;
        memcpy(nonce, state.nonce, 32);
        memcpy(context, state.rp_hash, 32);
        memcpy(context + 32, state.client_hash, 32);
        memcpy(sig, state.signature, 64);
        memcpy(pub, state.pub, 65);
        memcpy(id, state.id, 16);
        verify = true;
    }
    portEXIT_CRITICAL(&state_lock);
    if (verify) {
        uint8_t digest[32];
        request_digest(op, gen, nonce, context, id, digest);
        mbedtls_ecp_group g;
        mbedtls_ecp_point q;
        mbedtls_mpi r, s;
        mbedtls_ecp_group_init(&g);
        mbedtls_ecp_point_init(&q);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        int result = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
        if (!result)
            result = mbedtls_ecp_point_read_binary(&g, &q, pub, 65);
        if (!result)
            result = mbedtls_mpi_read_binary(&r, sig, 32);
        if (!result)
            result = mbedtls_mpi_read_binary(&s, sig + 32, 32);
        if (!result)
            result = mbedtls_ecdsa_verify(&g, digest, 32, &q, &r, &s);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecp_point_free(&q);
        mbedtls_ecp_group_free(&g);
        portENTER_CRITICAL(&state_lock);
        if (live() && gen == state.generation && !memcmp(nonce, state.nonce, 32)) {
            state.approved = result == 0;
            state.result = result == 0 ? 1 : 2;
        }
        portEXIT_CRITICAL(&state_lock);
    }
    bool approved = false;
    portENTER_CRITICAL(&state_lock);
    if (live() && state.approved) {
        approved = true;
        state.pending = state.approved = false;
        memset(state.nonce, 0, 32);
    }
    portEXIT_CRITICAL(&state_lock);
    return approved;
}
bool remote_presence_verify_digest(const uint8_t id[16], const uint8_t digest[32], const uint8_t sig[64]) {
    uint8_t pub[65];
    portENTER_CRITICAL(&state_lock);
    int slot = storage_ready ? find_id(id) : -1;
    if (slot >= 0) memcpy(pub, keys[slot], 65);
    portEXIT_CRITICAL(&state_lock);
    if (slot < 0) return false;
    mbedtls_ecp_group g;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_init(&g); mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    int result = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
    if (!result) result = mbedtls_ecp_point_read_binary(&g, &q, pub, 65);
    if (!result) result = mbedtls_mpi_read_binary(&r, sig, 32);
    if (!result) result = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    if (!result) result = mbedtls_ecdsa_verify(&g, digest, 32, &q, &r, &s);
    mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&g);
    portENTER_CRITICAL(&state_lock);
    slot = find_id(id);
    bool trusted = storage_ready && slot >= 0 && !memcmp(pub, keys[slot], 65);
    portEXIT_CRITICAL(&state_lock);
    return !result && trusted;
}
bool remote_presence_verify_any(const uint8_t digest[32], const uint8_t sig[64]) {
    uint8_t list[KEY_SLOTS][16];
    portENTER_CRITICAL(&state_lock);
    memcpy(list, ids, sizeof(list));
    portEXIT_CRITICAL(&state_lock);
    for (int i = 0; i < KEY_SLOTS; i++) {
        uint8_t any = 0;
        for (int j = 0; j < 16; j++)
            any |= list[i][j];
        if (any && remote_presence_verify_digest(list[i], digest, sig))
            return true;
    }
    return false;
}
uint16_t remote_presence_get(uint8_t report, uint8_t *b, uint16_t len) {
    if (report >= 16 && report <= 19) return remote_device_get(report, b, len);
    if (len < 63)
        return 0;
    memset(b, 0, 63);
    portENTER_CRITICAL(&state_lock);
    if (report == 1) {
        memcpy(b, "PRP2", 4);
        b[4] = live();
        b[5] = state.operation;
        b[6] = state.result;
        write32(b + 7, state.generation);
        write32(b + 11, live() ? AUTH_WINDOW_MS - (board_millis() - state.started) : 0);
        if (live())
            memcpy(b + 15, state.nonce, 32);
        memcpy(b + 47, state.id, 16);
    } else if (report == 2)
        memcpy(b, state.rp_hash, 32);
    else if (report == 9)
        memcpy(b, state.client_hash, 32);
    else if (report >= 5 && report <= 8)
        memcpy(b, state.rp + (report - 5) * 63, 63);
    else if (report == 10)
        memcpy(b, state.rp + 252, 4);
    else if (report == 12) {
        memcpy(b, "PRP2", 4);
        b[4] = pairing.phase;
        b[5] = pairing.result;
        b[7] = storage_ready && device_ready;
        for (int i = 0; i < KEY_SLOTS; i++)
            if (keys[i][0])
                b[6]++;
        memcpy(b + 8, pairing.tx, 16);
        memcpy(b + 24, pairing.id, 16);
        uint32_t elapsed = board_millis() - pairing.started;
        write32(b + 40, pair_active() && elapsed < PAIR_WINDOW_MS ? PAIR_WINDOW_MS - elapsed : 0);
        b[44] = KEY_SLOTS;
    } else if (report == 13)
        memcpy(b, ids, 48);
    else if (report == 14)
        memcpy(b, ids[3], 16);
    else if (report == 20 || report == 21) {
        // Device public key X and Y. Public data, read when pairing completes.
        if (device_ready)
            memcpy(b, device_pub + (report == 20 ? 1 : 33), 32);
    } else {
        portEXIT_CRITICAL(&state_lock);
        return 0;
    }
    portEXIT_CRITICAL(&state_lock);
    return 63;
}
void remote_presence_set(uint8_t report, const uint8_t *b, uint16_t len) {
    if (report >= 16 && report <= 19) { remote_device_set(report, b, len); return; }
    if (len != 63)
        return;
    portENTER_CRITICAL(&state_lock);
    if (report >= 12 && report <= 14) {
        if (report == 14 && b[16] == 0 && !memcmp(b, pairing.tx, 16) && pairing.phase != 6) {
            pairing.phase = 9;
            pairing.result = 7;
            pairing.staged = 0;
        } else if (!pair_active()) {
            if (report == 12) {
                memset(&pairing, 0, sizeof(pairing));
                memcpy(pairing.tx, b, 16);
                memcpy(pairing.pub, b + 16, 32);
                pairing.staged = 1;
                pairing.started = board_millis();
            } else if (report == 13 && pairing.staged == 1 && !memcmp(b, pairing.tx, 16)) {
                memcpy(pairing.pub + 32, b + 16, 33);
                pairing.staged = 2;
            } else if (report == 14 && !memcmp(b, pairing.tx, 16) &&
                       board_millis() - pairing.started < PAIR_WINDOW_MS &&
                       ((b[16] == 1 && pairing.staged == 2) ||
                        (b[16] == 2 && pairing.staged >= 1))) {
                pairing.action = b[16];
                if (b[16] == 2)
                    memcpy(pairing.id, b + 17, 16);
                pairing.phase = 1;
                pairing.result = 0;
                pairing.started = board_millis();
                pairing.staged = 0;
            }
        }
    } else if (report == 3 || report == 4 || report == 11) {
        if (!live() || state.approved || state.candidate || read32(b) != state.generation ||
            state.attempts >= 5) {
            state.result = 3;
            state.have_r = false;
        } else if (report == 11) {
            int slot = find_id(b + 4);
            state.selected = slot >= 0;
            state.have_r = false;
            if (slot >= 0) {
                memcpy(state.pub, keys[slot], 65);
                memcpy(state.id, ids[slot], 16);
            } else {
                state.result = 2;
                state.attempts++;
            }
        } else if (state.selected && report == 3) {
            memcpy(state.signature, b + 4, 32);
            state.have_r = true;
        } else if (state.selected && state.have_r && report == 4) {
            memcpy(state.signature + 32, b + 4, 32);
            state.have_r = false;
            state.candidate = true;
        }
    }
    portEXIT_CRITICAL(&state_lock);
}
#endif
