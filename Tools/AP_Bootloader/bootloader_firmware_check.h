#pragma once

#include <AP_CheckFirmware/AP_CheckFirmware.h>

#if AP_CHECK_FIRMWARE_ENABLED
check_fw_result_t bootloader_check_firmware(void);
void bootloader_check_indicate_leds(check_fw_result_t result);

#ifdef AP_BOOTLOADER_LOG_TO_SD
void bootloader_log_fw_result(check_fw_result_t result, bool will_boot);
#else
static inline void bootloader_log_fw_result(check_fw_result_t, bool) {}
#endif
#endif // AP_CHECK_FIRMWARE_ENABLED

void bootloader_check_report_usb(void);
