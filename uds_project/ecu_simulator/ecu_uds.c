#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ─── CAN IDs ─── */
#define ECU_RECV_ID  0x7DF
#define ECU_SEND_ID  0x7E8

/* ─── UDS Service IDs ─── */
#define SID_SESSION   0x10
#define SID_SEC_ACC   0x27
#define SID_READ_DID  0x22
#define SID_READ_DTC  0x19
#define SID_CLR_DTC   0x14
#define SID_TESTER    0x3E
#define SID_NEG_RESP  0x7F

/* ─── Sessions ─── */
#define SESSION_DEFAULT     0x01
#define SESSION_EXTENDED    0x03
#define SESSION_PROGRAMMING 0x02

/* ─── ECU State ─── */
uint8_t  current_session    = SESSION_DEFAULT;
uint8_t  security_unlocked  = 0;
uint8_t  security_attempts  = 0;
uint16_t current_seed       = 0;

/* ─── DTC Structure ─── */
typedef struct {
    uint8_t  byte1, byte2, byte3;
    uint8_t  status;
    char     desc[50];
} DTC_t;

DTC_t dtc_memory[] = {
    {0x01, 0x01, 0x18, 0x08, "Coolant Temp Sensor High"},
    {0x01, 0x00, 0x01, 0x08, "Fuel Volume Regulator"},
};
uint8_t dtc_count = 2;

/* ─── Compute Key from Seed ─── */
uint16_t compute_key(uint16_t seed) {
    return (uint16_t)((seed ^ 0xA5A5) + 0x1234) & 0xFFFF;
}

/* ─── Handle Session Control 0x10 ─── */
void handle_session(uint8_t *req, uint8_t *resp, uint8_t *len) {
    current_session = req[2];
    printf("[ECU] Session -> 0x%02X\n", current_session);
    resp[0] = 0x02;
    resp[1] = 0x50;
    resp[2] = req[2];
    *len = 3;
}

/* ─── Handle Security Access 0x27 ─── */
void handle_security(uint8_t *req, uint8_t *resp, uint8_t *len) {
    if (security_attempts >= 3) {
        printf("[ECU] LOCKED - too many attempts!\n");
        resp[0]=0x03; resp[1]=SID_NEG_RESP;
        resp[2]=SID_SEC_ACC; resp[3]=0x36;
        *len = 4; return;
    }
    if (req[2] == 0x01) {
        srand((unsigned)time(NULL));
        current_seed = (uint16_t)(rand() % 0xFFFF + 0x1000);
        printf("[ECU] Seed: 0x%04X\n", current_seed);
        resp[0] = 0x04; resp[1] = 0x67; resp[2] = 0x01;
        resp[3] = (current_seed >> 8) & 0xFF;
        resp[4] = current_seed & 0xFF;
        *len = 5;
    } else if (req[2] == 0x02) {
        uint16_t rk = (req[3] << 8) | req[4];
        uint16_t ek = compute_key(current_seed);
        if (rk == ek) {
            security_unlocked = 1;
            security_attempts = 0;
            printf("[ECU] UNLOCKED!\n");
            resp[0]=0x02; resp[1]=0x67; resp[2]=0x02;
            *len = 3;
        } else {
            security_attempts++;
            printf("[ECU] Wrong key! %d/3\n", security_attempts);
            resp[0]=0x03; resp[1]=SID_NEG_RESP;
            resp[2]=SID_SEC_ACC; resp[3]=0x35;
            *len = 4;
        }
    }
}

/* ─── Handle Read DID 0x22 ─── */
void handle_read_did(uint8_t *req, uint8_t *resp, uint8_t *len) {
    uint16_t did = (req[2] << 8) | req[3];
    if (did == 0xF190) {
        uint8_t vin[] = "1HGBH41JXMN109186";
        resp[0] = 20; resp[1] = 0x62;
        resp[2] = req[2]; resp[3] = req[3];
        memcpy(&resp[4], vin, 17);
        *len = 21;
        printf("[ECU] VIN sent\n");
    } else if (did == 0x0100) {
        resp[0]=0x05; resp[1]=0x62;
        resp[2]=req[2]; resp[3]=req[3];
        resp[4]=0x0B; resp[5]=0xB8;
        *len = 6;
        printf("[ECU] RPM = 3000\n");
    } else if (did == 0x0101) {
        resp[0]=0x04; resp[1]=0x62;
        resp[2]=req[2]; resp[3]=req[3];
        resp[4]=0x55;
        *len = 5;
        printf("[ECU] Temp = 85C\n");
    } else {
        resp[0]=0x03; resp[1]=SID_NEG_RESP;
        resp[2]=SID_READ_DID; resp[3]=0x31;
        *len = 4;
    }
}

/* ─── Handle Read DTC 0x19 ─── */
void handle_read_dtc(uint8_t *resp, uint8_t *len) {
    resp[0] = 0x00;
    resp[1] = 0x59;
    resp[2] = 0x02;
    uint8_t i = 3;
    for (int d = 0; d < dtc_count; d++) {
        resp[i++] = dtc_memory[d].byte1;
        resp[i++] = dtc_memory[d].byte2;
        resp[i++] = dtc_memory[d].byte3;
        resp[i++] = dtc_memory[d].status;
        printf("[ECU] DTC: %s\n", dtc_memory[d].desc);
    }
    resp[0] = i - 1;
    *len = i;
}

/* ─── Handle Clear DTC 0x14 ─── */
void handle_clear_dtc(uint8_t *resp, uint8_t *len) {
    dtc_count = 0;
    printf("[ECU] All DTCs cleared!\n");
    resp[0] = 0x01;
    resp[1] = 0x54;
    *len = 2;
}

/* ─── Main UDS Dispatcher ─── */
void uds_process(uint8_t *req, uint8_t *resp, uint8_t *len) {
    uint8_t sid = req[1];
    printf("\n[ECU] Service: 0x%02X\n", sid);
    switch (sid) {
        case SID_SESSION:  handle_session(req, resp, len);   break;
        case SID_SEC_ACC:  handle_security(req, resp, len);  break;
        case SID_READ_DID: handle_read_did(req, resp, len);  break;
        case SID_READ_DTC: handle_read_dtc(resp, len);       break;
        case SID_CLR_DTC:  handle_clear_dtc(resp, len);      break;
        case SID_TESTER:
            resp[0]=0x02; resp[1]=0x7E; resp[2]=0x00;
            *len = 3; break;
        default:
            resp[0]=0x03; resp[1]=SID_NEG_RESP;
            resp[2]=sid;  resp[3]=0x11;
            *len = 4;
    }
}

/* ─── Simulate CAN frame print ─── */
void print_frame(const char *label, uint32_t id, uint8_t *data, uint8_t len) {
    printf("%s ID=0x%03X  [%d]  ", label, id, len);
    for (int i = 0; i < len; i++) printf("%02X ", data[i]);
    printf("\n");
}

/* ─── Main ─── */
int main() {
    printf("========================================\n");
    printf("  UDS ECU SIMULATOR - C Version\n");
    printf("  ISO 14229 | Bosch/Visteon Ready\n");
    printf("========================================\n\n");

    /* Simulate 7 UDS requests */
    uint8_t requests[][8] = {
        {0x02, 0x10, 0x03, 0,0,0,0,0},  /* Enter Extended Session */
        {0x02, 0x27, 0x01, 0,0,0,0,0},  /* Request Seed           */
        {0x04, 0x27, 0x02, 0,0,0,0,0},  /* Send Key (filled below)*/
        {0x03, 0x22, 0xF1,0x90,0,0,0,0},/* Read VIN               */
        {0x03, 0x22, 0x01,0x00,0,0,0,0},/* Read RPM               */
        {0x03, 0x19, 0x02,0xFF,0,0,0,0},/* Read DTCs              */
        {0x04, 0x14, 0xFF,0xFF,0xFF,0,0,0}, /* Clear DTCs          */
    };

    uint8_t resp[32];
    uint8_t resp_len;

    for (int i = 0; i < 7; i++) {
        /* Fill key in step 3 using seed from step 2 */
        if (i == 2) {
            uint16_t key = compute_key(current_seed);
            requests[2][3] = (key >> 8) & 0xFF;
            requests[2][4] = key & 0xFF;
        }
        print_frame("[TESTER->ECU]", ECU_RECV_ID, requests[i], requests[i][0]+1);
        memset(resp, 0, sizeof(resp));
        uds_process(requests[i], resp, &resp_len);
        print_frame("[ECU->TESTER]", ECU_SEND_ID, resp, resp_len);
    }

    printf("\n========================================\n");
    printf("  SIMULATION COMPLETE!\n");
    printf("========================================\n");
    return 0;
}
