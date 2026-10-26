/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "pico_keys.h"

#ifdef ESP_PLATFORM

#include "driver/rmt_tx.h"
#include "esp_rom_sys.h"

// One WS2812 pixel over RMT. Every frame ends with the line held low (the
// WS2812 reset state). ESP32-S3 SuperMini also wires a red LED to this line
// (GPIO48 -> 1K -> LED -> GND), so an idle-high line would light it, and the
// I2S driver used before released the line high after each frame, which some
// pixels latched as a stray green bit.
#define NP_RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))
#define RMT_RESOLUTION_HZ 10000000 // 0.1 us ticks

static rmt_channel_handle_t channel = NULL;
static rmt_encoder_handle_t encoder = NULL;
static bool sent = false;
static uint32_t last_rgb = 0;

static const uint32_t pixel[] = {
    NP_RGB(0,  0,  0),     /* off */
    NP_RGB(255,  0, 0),    /* red */
    NP_RGB(0, 255,  0),    /* green */
    NP_RGB(0, 0,  255),    /* blue */
    NP_RGB(255,  255, 0),  /* yellow */
    NP_RGB(255,  0, 255),  /* magenta */
    NP_RGB(0, 255,  255),  /* cyan */
    NP_RGB(255, 255,  255) /* white */
};

#if defined(CONFIG_IDF_TARGET_ESP32S3)
    #define NEOPIXEL_PIN GPIO_NUM_48
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #define NEOPIXEL_PIN GPIO_NUM_15
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #define NEOPIXEL_PIN GPIO_NUM_8
#else
    #define NEOPIXEL_PIN GPIO_NUM_27
#endif

void led_driver_init_neopixel() {
    uint8_t gpio = NEOPIXEL_PIN;
    if (phy_data.led_gpio_present) {
        gpio = phy_data.led_gpio;
    }
    rmt_tx_channel_config_t tx = {
        .gpio_num = gpio,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = RMT_RESOLUTION_HZ,
        .mem_block_symbols = 48, // 24 data bits fit without refills
        .trans_queue_depth = 1,
    };
    rmt_bytes_encoder_config_t bytes = {
        .bit0 = {.level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9}, // 0.3 us high, 0.9 us low
        .bit1 = {.level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3}, // 0.9 us high, 0.3 us low
        .flags.msb_first = 1,
    };
    if (rmt_new_tx_channel(&tx, &channel) != ESP_OK || rmt_new_bytes_encoder(&bytes, &encoder) != ESP_OK ||
        rmt_enable(channel) != ESP_OK) {
        channel = NULL;
    }
}

void led_driver_color_neopixel(uint8_t color, uint32_t led_brightness, float progress) {
    if (!channel) {
        return;
    }
    if (!(phy_data.opts & PHY_OPT_DIMM)) {
        progress = progress >= 0.5 ? 1 : 0;
    }
    uint32_t led_phy_btness = phy_data.led_brightness_present ? phy_data.led_brightness : MAX_BTNESS;
    float brightness = ((float)led_brightness / MAX_BTNESS) * ((float)led_phy_btness / MAX_BTNESS) * progress;
    uint32_t pixel_color = pixel[color & 7];
    uint8_t r = (uint8_t)(((pixel_color >> 16) & 0xFF) * brightness);
    uint8_t g = (uint8_t)(((pixel_color >> 8) & 0xFF) * brightness);
    uint8_t b = (uint8_t)((pixel_color & 0xFF) * brightness);
    uint32_t rgb = NP_RGB(r, g, b);
    // Resend only on change: every frame also flickers the shared red LED.
    if (sent && rgb == last_rgb) {
        return;
    }
    if (rmt_tx_wait_all_done(channel, 10) != ESP_OK) {
        return;
    }
    esp_rom_delay_us(80); // idle low past the WS2812 reset time before the next frame
    static uint8_t grb[3];
    grb[0] = g; grb[1] = r; grb[2] = b;
    rmt_transmit_config_t frame = {.loop_count = 0, .flags.eot_level = 0};
    if (rmt_transmit(channel, encoder, grb, sizeof(grb), &frame) == ESP_OK) {
        sent = true;
        last_rgb = rgb;
    }
}

led_driver_t led_driver_neopixel = {
    .init = led_driver_init_neopixel,
    .set_color = led_driver_color_neopixel,
};

#endif
