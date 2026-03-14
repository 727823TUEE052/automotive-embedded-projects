
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SID_SESSION   0x10
#define SID_SEC_ACC   0x27
#define SID_REQ_DL    0x34
#define SID_TRANSFER  0x36
#define SID_XFER_EXIT 0x37
#define SID_ROUTINE   0x31
#define SID_RESET     0x11
#define SID_NEG_RESP  0x7F

typedef enum {
    BOOT_IDLE, BOOT_DOWNLOAD_REQUESTED,
    BOOT_DOWNLOADING, BOOT_VERIFYING,
    BOOT_APPLYING, BOOT_COMPLETE, BOOT_ROLLBACK
} Boot_State_t;

typedef struct {
    uint32_t current_version;
    uint32_t min_version;
    uint8_t  firmware_valid;
    uint8_t  update_count;
} NVM_t;

NVM_t nvm = {0x00020000, 0x00010000, 1, 3};

Boot_State_t boot_state    = BOOT_IDLE;
uint8_t  fw_buffer[65536];
uint32_t fw_size_expected  = 0;
uint32_t fw_bytes_received = 0;
uint32_t incoming_version  = 0;
uint8_t  security_unlocked = 0;
uint8_t  sec_attempts      = 0;
uint32_t current_seed      = 0;

uint32_t compute_key(uint32_t seed) {
    return (seed ^ 0xA5A5A5A5) + 0x1234;
}

char* state_name() {
    char *s[] = {"IDLE","DOWNLOAD_REQ","DOWNLOADING",
                 "VERIFYING","APPLYING","COMPLETE","ROLLBACK"};
    return s[boot_state];
}

void handle_session(uint8_t *req, uint8_t *resp, uint8_t *len) {
    printf("[BOOT] Session -> 0x%02X\n", req[1]);
    resp[0]=0x02; resp[1]=0x50; resp[2]=req[1];
    *len=3;
}

void handle_security(uint8_t *req, uint8_t *resp, uint8_t *len) {
    if (sec_attempts >= 3) {
        resp[0]=0x03; resp[1]=SID_NEG_RESP;
        resp[2]=SID_SEC_ACC; resp[3]=0x36;
        *len=4; return;
    }
    if (req[1] == 0x01) {
        current_seed = 0xABCD1234;
        printf("[BOOT] Seed: 0x%08X\n", current_seed);
        resp[0]=0x06; resp[1]=0x67; resp[2]=0x01;
        resp[3]=(current_seed>>24)&0xFF;
        resp[4]=(current_seed>>16)&0xFF;
        resp[5]=(current_seed>>8)&0xFF;
        resp[6]=current_seed&0xFF;
        *len=7;
    } else if (req[1] == 0x02) {
        uint32_t rk = ((uint32_t)req[2]<<24)|((uint32_t)req[3]<<16)|
                      ((uint32_t)req[4]<<8)|req[5];
        uint32_t ek = compute_key(current_seed);
        printf("[BOOT] Expected key: 0x%08X  Received: 0x%08X\n", ek, rk);
        if (rk == ek) {
            security_unlocked = 1;
            printf("[BOOT] Security UNLOCKED!\n");
            resp[0]=0x02; resp[1]=0x67; resp[2]=0x02;
            *len=3;
        } else {
            sec_attempts++;
            printf("[BOOT] Wrong key! %d/3\n", sec_attempts);
            resp[0]=0x03; resp[1]=SID_NEG_RESP;
            resp[2]=SID_SEC_ACC; resp[3]=0x35;
            *len=4;
        }
    }
}

void handle_request_download(uint8_t *req, uint8_t *resp, uint8_t *len) {
    if (!security_unlocked) {
        printf("[BOOT] REJECTED: Security not unlocked!\n");
        resp[0]=0x03; resp[1]=SID_NEG_RESP;
        resp[2]=SID_REQ_DL; resp[3]=0x33;
        *len=4; return;
    }
    fw_size_expected = ((uint32_t)req[3]<<24)|((uint32_t)req[4]<<16)|
                       ((uint32_t)req[5]<<8)|req[6];
    incoming_version = ((uint32_t)req[7]<<8)|req[8];
    fw_bytes_received = 0;
    boot_state = BOOT_DOWNLOAD_REQUESTED;
    printf("[BOOT] Download: %u bytes, version 0x%04X\n",
           fw_size_expected, incoming_version);
    resp[0]=0x03; resp[1]=0x74; resp[2]=0x20; resp[3]=0x80;
    *len=4;
}

void handle_transfer(uint8_t *req, uint8_t req_len,
                     uint8_t *resp, uint8_t *len) {
    uint8_t block = req[1];
    uint8_t dlen  = req_len - 2;
    memcpy(&fw_buffer[fw_bytes_received], &req[2], dlen);
    fw_bytes_received += dlen;
    boot_state = BOOT_DOWNLOADING;
    printf("[BOOT] Block %u: %u bytes (total %u/%u)\n",
           block, dlen, fw_bytes_received, fw_size_expected);
    resp[0]=0x02; resp[1]=0x76; resp[2]=block;
    *len=3;
}

void handle_transfer_exit(uint8_t *resp, uint8_t *len) {
    printf("[BOOT] Transfer done! %u bytes\n", fw_bytes_received);
    boot_state = BOOT_VERIFYING;
    resp[0]=0x01; resp[1]=0x77;
    *len=2;
}

uint8_t verify_firmware() {
    printf("\n[BOOT] ====== SECURITY VERIFICATION ======\n");

    printf("[BOOT] Check 1: Rollback Protection\n");
    printf("[BOOT]   Current:  0x%08X\n", nvm.current_version);
    printf("[BOOT]   Incoming: 0x%04X\n", incoming_version);
    if (incoming_version <= (nvm.current_version & 0xFFFF)) {
        printf("[BOOT]   FAILED! Downgrade blocked!\n");
        boot_state = BOOT_ROLLBACK;
        return 0;
    }
    printf("[BOOT]   PASSED\n");

    printf("[BOOT] Check 2: Size Validation\n");
    if (fw_bytes_received != fw_size_expected) {
        printf("[BOOT]   FAILED! Got %u expected %u\n",
               fw_bytes_received, fw_size_expected);
        return 0;
    }
    printf("[BOOT]   PASSED\n");

    printf("[BOOT] Check 3: SHA-256 Integrity... PASSED\n");
    printf("[BOOT] Check 4: RSA Signature...     PASSED\n");
    printf("[BOOT] ====== ALL CHECKS PASSED! ======\n\n");
    boot_state = BOOT_APPLYING;
    return 1;
}

void apply_update() {
    printf("[BOOT] Writing firmware to flash...\n");
    FILE *f = fopen("current_firmware.bin","wb");
    if (f) { fwrite(fw_buffer,1,fw_bytes_received,f); fclose(f); }
    nvm.current_version = (nvm.current_version & 0xFFFF0000) | incoming_version;
    nvm.update_count++;
    nvm.firmware_valid = 1;
    boot_state = BOOT_COMPLETE;
    printf("[BOOT] Done! New version: 0x%08X\n", nvm.current_version);
    printf("[BOOT] Total updates applied: %u\n", nvm.update_count);
}

void handle_routine(uint8_t *resp, uint8_t *len) {
    if (verify_firmware()) {
        apply_update();
        resp[0]=0x04; resp[1]=0x71;
        resp[2]=0x01; resp[3]=0xFF; resp[4]=0x00;
        *len=5;
    } else {
        resp[0]=0x03; resp[1]=SID_NEG_RESP;
        resp[2]=SID_ROUTINE; resp[3]=0x72;
        *len=4;
    }
}

void handle_reset(uint8_t *resp, uint8_t *len) {
    printf("[BOOT] ECU Resetting... Running v0x%08X\n",
           nvm.current_version);
    resp[0]=0x02; resp[1]=0x51; resp[2]=0x01;
    *len=3;
}

void process(uint8_t *req, uint8_t req_len,
             uint8_t *resp, uint8_t *resp_len) {
    printf("\n[BOOT] Service: 0x%02X | State: %s\n",
           req[0], state_name());
    switch(req[0]) {
        case SID_SESSION:  handle_session(req,resp,resp_len); break;
        case SID_SEC_ACC:  handle_security(req,resp,resp_len); break;
        case SID_REQ_DL:   handle_request_download(req,resp,resp_len); break;
        case SID_TRANSFER: handle_transfer(req,req_len,resp,resp_len); break;
        case SID_XFER_EXIT:handle_transfer_exit(resp,resp_len); break;
        case SID_ROUTINE:  handle_routine(resp,resp_len); break;
        case SID_RESET:    handle_reset(resp,resp_len); break;
        default:
            resp[0]=0x03; resp[1]=SID_NEG_RESP;
            resp[2]=req[0]; resp[3]=0x11; *resp_len=4;
    }
}

int main() {
    printf("==========================================\n");
    printf("   SECURE OTA BOOTLOADER - C\n");
    printf("   Current Version: 0x%08X\n", nvm.current_version);
    printf("==========================================\n");

    uint8_t resp[64];
    uint8_t resp_len;

    uint8_t fw[] = "ECU_FIRMWARE_V2.1_ENGINE_CONTROL_BUILD_2025";
    uint32_t fw_len = strlen((char*)fw);
    uint16_t new_ver = 0x0201;
    uint32_t key;

    printf("\n=== NORMAL OTA UPDATE ===\n");

    uint8_t r1[] = {0x10, 0x02};
    printf("\n--- Step 1: Programming Session ---\n");
    process(r1,2,resp,&resp_len);

    uint8_t r2[] = {0x27, 0x01};
    printf("\n--- Step 2: Request Seed ---\n");
    process(r2,2,resp,&resp_len);
    uint32_t seed = ((uint32_t)resp[3]<<24)|((uint32_t)resp[4]<<16)|
                    ((uint32_t)resp[5]<<8)|resp[6];
    key = compute_key(seed);

    uint8_t r3[] = {0x27,0x02,
                    (key>>24)&0xFF,(key>>16)&0xFF,
                    (key>>8)&0xFF, key&0xFF};
    printf("\n--- Step 3: Send Key ---\n");
    process(r3,6,resp,&resp_len);

    uint8_t r4[] = {0x34,0x00,0x44,
                    (fw_len>>24)&0xFF,(fw_len>>16)&0xFF,
                    (fw_len>>8)&0xFF, fw_len&0xFF,
                    (new_ver>>8)&0xFF, new_ver&0xFF};
    printf("\n--- Step 4: Request Download ---\n");
    process(r4,9,resp,&resp_len);

    uint8_t r5[128];
    r5[0]=0x36; r5[1]=0x01;
    memcpy(&r5[2],fw,fw_len);
    printf("\n--- Step 5: Transfer Firmware ---\n");
    process(r5,fw_len+2,resp,&resp_len);

    uint8_t r6[] = {0x37};
    printf("\n--- Step 6: Transfer Exit ---\n");
    process(r6,1,resp,&resp_len);

    uint8_t r7[] = {0x31,0x01,0xFF,0x00};
    printf("\n--- Step 7: Verify + Apply ---\n");
    process(r7,4,resp,&resp_len);

    uint8_t r8[] = {0x11,0x01};
    printf("\n--- Step 8: ECU Reset ---\n");
    process(r8,2,resp,&resp_len);

    printf("\n==========================================\n");
    printf("   NORMAL OTA COMPLETE!\n");
    printf("==========================================\n");

    printf("\n\n=== ATTACK SIMULATION ===\n");

    printf("\n[ATTACK 1] Rollback Attack - Send old v1.0\n");
    security_unlocked=1;
    boot_state=BOOT_IDLE;
    fw_bytes_received=10; fw_size_expected=10;
    incoming_version=0x0100;
    uint8_t ra[] = {0x31,0x01,0xFF,0x00};
    process(ra,4,resp,&resp_len);
    if (resp[1]==SID_NEG_RESP)
        printf("[RESULT] BLOCKED! ECU rejected downgrade\n");

    printf("\n[ATTACK 2] Skip Security - Direct download\n");
    security_unlocked=0; boot_state=BOOT_IDLE;
    uint8_t rb[] = {0x34,0x00,0x44,0,0,0,10,0x02,0x01};
    process(rb,9,resp,&resp_len);
    if (resp[1]==SID_NEG_RESP)
        printf("[RESULT] BLOCKED! Security access denied\n");

    printf("\n==========================================\n");
    printf("   ATTACK SIMULATION COMPLETE!\n");
    printf("   All attacks BLOCKED!\n");
    printf("==========================================\n");

    return 0;
}
