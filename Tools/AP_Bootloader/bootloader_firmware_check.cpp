#include "bootloader_firmware_check.h"

#include "hwdef.h"
#include "support.h"

#include <stddef.h>
#include <string.h>

#if AP_CHECK_FIRMWARE_ENABLED

#if defined(HAL_BOOTLOADER_REQUIRE_SIGNED_FIRMWARE) && !AP_SIGNED_FIRMWARE
#error "HAL_BOOTLOADER_REQUIRE_SIGNED_FIRMWARE requires AP_SIGNED_FIRMWARE=1"
#endif

#ifdef HAL_BOOTLOADER_FIXED_APP_SHA256
static const uint8_t fixed_app_sha256[32] = HAL_BOOTLOADER_FIXED_APP_SHA256;
#endif

static check_fw_result_t last_check_result = check_fw_result_t::FAIL_REASON_NO_APP_SIG;
static bool usb_report_sent;
static bool led_status_shown;

struct sha256_context {
    uint64_t bit_count;
    uint32_t state[8];
    uint8_t buffer[64];
    uint8_t buffer_len;
};

static uint32_t sha256_rotr(uint32_t v, uint32_t n)
{
    return (v >> n) | (v << (32U - n));
}

static uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sha256_ep0(uint32_t x)
{
    return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22);
}

static uint32_t sha256_ep1(uint32_t x)
{
    return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25);
}

static uint32_t sha256_sig0(uint32_t x)
{
    return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3);
}

static uint32_t sha256_sig1(uint32_t x)
{
    return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10);
}

static void sha256_transform(sha256_context &ctx, const uint8_t data[64])
{
    static const uint32_t k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t m[64];
    for (uint8_t i = 0; i < 16; i++) {
        const uint8_t j = i * 4U;
        m[i] = (uint32_t(data[j]) << 24) |
               (uint32_t(data[j + 1]) << 16) |
               (uint32_t(data[j + 2]) << 8) |
               uint32_t(data[j + 3]);
    }
    for (uint8_t i = 16; i < 64; i++) {
        m[i] = sha256_sig1(m[i - 2]) + m[i - 7] + sha256_sig0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];
    uint32_t e = ctx.state[4];
    uint32_t f = ctx.state[5];
    uint32_t g = ctx.state[6];
    uint32_t h = ctx.state[7];

    for (uint8_t i = 0; i < 64; i++) {
        const uint32_t t1 = h + sha256_ep1(e) + sha256_ch(e, f, g) + k[i] + m[i];
        const uint32_t t2 = sha256_ep0(a) + sha256_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

static void sha256_init(sha256_context &ctx)
{
    ctx.bit_count = 0;
    ctx.buffer_len = 0;
    ctx.state[0] = 0x6a09e667U;
    ctx.state[1] = 0xbb67ae85U;
    ctx.state[2] = 0x3c6ef372U;
    ctx.state[3] = 0xa54ff53aU;
    ctx.state[4] = 0x510e527fU;
    ctx.state[5] = 0x9b05688cU;
    ctx.state[6] = 0x1f83d9abU;
    ctx.state[7] = 0x5be0cd19U;
}

static void sha256_update(sha256_context &ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        ctx.buffer[ctx.buffer_len++] = data[i];
        if (ctx.buffer_len == sizeof(ctx.buffer)) {
            sha256_transform(ctx, ctx.buffer);
            ctx.bit_count += sizeof(ctx.buffer) * 8U;
            ctx.buffer_len = 0;
        }
    }
}

static void sha256_final(sha256_context &ctx, uint8_t hash[32])
{
    ctx.bit_count += uint64_t(ctx.buffer_len) * 8U;
    ctx.buffer[ctx.buffer_len++] = 0x80U;

    if (ctx.buffer_len > 56U) {
        while (ctx.buffer_len < 64U) {
            ctx.buffer[ctx.buffer_len++] = 0;
        }
        sha256_transform(ctx, ctx.buffer);
        ctx.buffer_len = 0;
    }

    while (ctx.buffer_len < 56U) {
        ctx.buffer[ctx.buffer_len++] = 0;
    }

    for (uint8_t i = 0; i < 8; i++) {
        ctx.buffer[63U - i] = uint8_t(ctx.bit_count >> (i * 8U));
    }
    sha256_transform(ctx, ctx.buffer);

    for (uint8_t i = 0; i < 8; i++) {
        hash[i * 4U]     = uint8_t(ctx.state[i] >> 24);
        hash[i * 4U + 1] = uint8_t(ctx.state[i] >> 16);
        hash[i * 4U + 2] = uint8_t(ctx.state[i] >> 8);
        hash[i * 4U + 3] = uint8_t(ctx.state[i]);
    }
}

static bool calculate_sha256(const uint8_t *flash1, uint32_t len1,
                             const uint8_t *flash2, uint32_t len2,
                             uint8_t hash[32])
{
    sha256_context ctx {};
    sha256_init(ctx);
    sha256_update(ctx, flash1, len1);
    sha256_update(ctx, flash2, len2);
    sha256_final(ctx, hash);
    return true;
}

static const uint8_t *get_app_flash_base(void)
{
    return (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB) * 1024U);
}

static uint32_t get_app_flash_size(void)
{
    return (BOARD_FLASH_SIZE - (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)) * 1024U;
}

template <typename Descriptor>
static const Descriptor *find_descriptor(const uint8_t *sig)
{
    const uint8_t *flash = get_app_flash_base();
    const uint32_t flash_size = get_app_flash_size();
    return (const Descriptor *)memmem(flash, flash_size - sizeof(Descriptor), sig, 8U);
}

template <typename Descriptor>
static bool descriptor_sha256_matches(const Descriptor *ad, uint8_t image_sha256[32])
{
    if (ad == nullptr) {
        return false;
    }

    const uint8_t *flash1 = get_app_flash_base();
    const uint8_t *flash2 = (const uint8_t *)&ad->version_major;
    const uint32_t len1 = ((const uint8_t *)&ad->image_crc1) - flash1;
    const uint8_t desc_len = offsetof(Descriptor, version_major) - offsetof(Descriptor, image_crc1);

    if ((len1 + desc_len) > ad->image_size) {
        return false;
    }

    const uint32_t len2 = ad->image_size - (len1 + desc_len);
    return calculate_sha256(flash1, len1, flash2, len2, image_sha256);
}

static uint8_t led_pulse_count(check_fw_result_t result)
{
    switch (result) {
    case check_fw_result_t::CHECK_FW_OK:
        return 0;
    case check_fw_result_t::FAIL_REASON_BAD_CRC:
        return 2;
    case check_fw_result_t::FAIL_REASON_BAD_FIRMWARE_SIGNATURE:
        return 3;
    case check_fw_result_t::FAIL_REASON_BAD_SHA256:
        return 4;
    case check_fw_result_t::FAIL_REASON_VERIFICATION:
        return 5;
    default:
        return 1;
    }
}

static const char *result_name(check_fw_result_t result)
{
    switch (result) {
    case check_fw_result_t::CHECK_FW_OK:
        return "FW_OK";
    case check_fw_result_t::FAIL_REASON_NO_APP_SIG:
        return "NO_APP_SIG";
    case check_fw_result_t::FAIL_REASON_BAD_LENGTH_APP:
        return "BAD_APP_LENGTH";
    case check_fw_result_t::FAIL_REASON_BAD_BOARD_ID:
        return "BAD_BOARD_ID";
    case check_fw_result_t::FAIL_REASON_BAD_CRC:
        return "BAD_CRC";
    case check_fw_result_t::FAIL_REASON_IN_UPDATE:
        return "IN_UPDATE";
    case check_fw_result_t::FAIL_REASON_WATCHDOG:
        return "WATCHDOG";
    case check_fw_result_t::FAIL_REASON_BAD_LENGTH_DESCRIPTOR:
        return "BAD_DESC_LENGTH";
    case check_fw_result_t::FAIL_REASON_BAD_FIRMWARE_SIGNATURE:
        return "BAD_SIGNATURE";
    case check_fw_result_t::FAIL_REASON_VERIFICATION:
        return "VERIFICATION_FAIL";
    case check_fw_result_t::FAIL_REASON_BAD_SHA256:
        return "BAD_SHA256";
    }
    return "UNKNOWN";
}

#ifdef AP_BOOTLOADER_LOG_TO_SD
#include <AP_HAL_ChibiOS/sdcard.h>
#include <ff.h>

/*
 * Log firmware verification result to SD card when available.
 * Keeps runtime minimal and only tries once per boot.
 */
void bootloader_log_fw_result(check_fw_result_t result, bool will_boot)
{
    static bool logged;
    if (logged) {
        return;
    }
    logged = true;

    if (!sdcard_init()) {
        return;
    }

    FIL fp;
    const char *path = "/bootloader.log";
    if (f_open(&fp, path, FA_OPEN_APPEND | FA_WRITE) != FR_OK) {
        sdcard_stop();
        return;
    }

    char line[96];
    const int len = snprintf(line, sizeof(line), "FW %s: %s\r\n",
                             will_boot ? "OK" : "INVALID",
                             result_name(result));
    if (len > 0) {
        UINT written = 0;
        f_write(&fp, line, (UINT)len, &written);
    }

    f_close(&fp);
    sdcard_stop();
}
#endif

void bootloader_check_indicate_leds(check_fw_result_t result)
{
    if (led_status_shown) {
        return;
    }
    led_status_shown = true;

    if (result == check_fw_result_t::CHECK_FW_OK) {
        led_on(LED_BOOTLOADER);
        thread_sleep_ms(250);
        led_off(LED_BOOTLOADER);
        thread_sleep_ms(100);
        return;
    }

    const uint8_t pulses = led_pulse_count(result);
    for (uint8_t i = 0; i < pulses; i++) {
        led_on(LED_BOOTLOADER);
        thread_sleep_ms(180);
        led_off(LED_BOOTLOADER);
        thread_sleep_ms(180);
    }
    thread_sleep_ms(350);
}

void bootloader_check_report_usb(void)
{
    if (usb_report_sent) {
        return;
    }
    usb_report_sent = true;
    usb_printf("Boot check: %s (%u)\r\n",
               result_name(last_check_result),
               unsigned(last_check_result));
}

check_fw_result_t bootloader_check_firmware(void)
{
#ifdef HAL_BOOTLOADER_REQUIRE_SIGNED_FIRMWARE
    static const uint8_t signed_sig[8] = AP_APP_DESCRIPTOR_SIGNATURE_SIGNED;
    const auto *signed_desc = find_descriptor<app_descriptor_signed>(signed_sig);
    if (signed_desc == nullptr) {
        last_check_result = check_fw_result_t::FAIL_REASON_BAD_FIRMWARE_SIGNATURE;
        return last_check_result;
    }
#endif

    last_check_result = check_good_firmware();
    if (last_check_result != check_fw_result_t::CHECK_FW_OK) {
        return last_check_result;
    }

    uint8_t image_sha256[32];
#if AP_SIGNED_FIRMWARE || defined(HAL_BOOTLOADER_REQUIRE_SIGNED_FIRMWARE)
    if (signed_desc != nullptr) {
        if (!descriptor_sha256_matches(signed_desc, image_sha256)) {
            last_check_result = check_fw_result_t::FAIL_REASON_BAD_SHA256;
            return last_check_result;
        }
#ifdef HAL_BOOTLOADER_FIXED_APP_SHA256
        last_check_result = memcmp(image_sha256, fixed_app_sha256, sizeof(image_sha256)) == 0 ?
            check_fw_result_t::CHECK_FW_OK :
            check_fw_result_t::FAIL_REASON_BAD_SHA256;
#else
        last_check_result = memcmp(image_sha256, signed_desc->image_sha256, sizeof(image_sha256)) == 0 ?
            check_fw_result_t::CHECK_FW_OK :
            check_fw_result_t::FAIL_REASON_BAD_SHA256;
#endif
        return last_check_result;
    }
#endif

    static const uint8_t unsigned_sig[8] = AP_APP_DESCRIPTOR_SIGNATURE_UNSIGNED;
    const auto *unsigned_desc = find_descriptor<app_descriptor_unsigned>(unsigned_sig);
    if (unsigned_desc != nullptr) {
        if (!descriptor_sha256_matches(unsigned_desc, image_sha256)) {
            last_check_result = check_fw_result_t::FAIL_REASON_BAD_SHA256;
            return last_check_result;
        }
#ifdef HAL_BOOTLOADER_FIXED_APP_SHA256
        last_check_result = memcmp(image_sha256, fixed_app_sha256, sizeof(image_sha256)) == 0 ?
            check_fw_result_t::CHECK_FW_OK :
            check_fw_result_t::FAIL_REASON_BAD_SHA256;
#else
        last_check_result = memcmp(image_sha256, unsigned_desc->image_sha256, sizeof(image_sha256)) == 0 ?
            check_fw_result_t::CHECK_FW_OK :
            check_fw_result_t::FAIL_REASON_BAD_SHA256;
#endif
        return last_check_result;
    }

    last_check_result = check_fw_result_t::FAIL_REASON_NO_APP_SIG;
    return last_check_result;
}

#else // AP_CHECK_FIRMWARE_ENABLED

void bootloader_check_report_usb(void)
{
}

#endif // AP_CHECK_FIRMWARE_ENABLED
