/*
 * AFL++ harness: feed 12-byte records (4-byte BE CAN ID + 8-byte payload)
 * into Open-SAE-J1939 Listen_For_Messages via INTERNAL_CALLBACK.
 *
 * Research / portfolio only. Target is MIT-licensed Open-SAE-J1939.
 */
#define OPENSAE_J1939_TARGET_PLATFORM INTERNAL_CALLBACK

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "Open_SAE_J1939/Open_SAE_J1939.h"

static uint32_t g_id;
static uint8_t g_data[8];
static bool g_have;

static void send_cb(uint32_t id, uint8_t dlc, uint8_t data[]) {
    (void)id;
    (void)dlc;
    (void)data;
}

static void read_cb(uint32_t *id, uint8_t data[], bool *is_new) {
    if (!g_have) {
        *is_new = false;
        return;
    }
    *id = g_id;
    memcpy(data, g_data, 8);
    *is_new = true;
    g_have = false;
}

static void delay_cb(uint8_t ms) { (void)ms; }

int main(void) {
    J1939 j1939;
    memset(&j1939, 0, sizeof(j1939));
    j1939.information_this_ECU.this_ECU_address = 0xA2;
    CAN_Set_Callback_Functions(send_cb, read_cb, NULL, delay_cb);

    uint8_t buf[12];
    while (read(0, buf, 12) == 12) {
        g_id = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
               ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
        memcpy(g_data, buf + 4, 8);
        g_have = true;
        Open_SAE_J1939_Listen_For_Messages(&j1939);
    }
    return 0;
}
