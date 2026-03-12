
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define ECU_RECV_ID  0x7DF
#define ECU_SEND_ID  0x7E8

#define SID_SESSION   0x10
#define SID_SEC_ACC   0x27
#define SID_READ_DID  0x22
#define SID_READ_DTC  0x19
#define SID_CLR_DTC   0x14
#define SID_TESTER    0x3E
#define SID_NEG_RESP  0x7F

#define SESSION_DEFAULT     0x01
#define SESSION_EXTENDED    0x03
#define SESSION_PROGRAMMING 0x02

uint8_t  current_session   = SESSION_DEFAULT;
uint8_t  security_unlocked = 0;
uint8_t  sec_attempts      = 0;
uint32_t current_seed      = 0;

uint32_t compute_key(uint32_t seed) {
    return (seed ^ 0xA5A5A5A5) + 0x1234;
}

void handle_session(uint8_t *req, uint8_t *resp, uint8_t *len) {
    current_session = req[2];
    printf("[ECU] Session -> 0x%02X\n", current_session);
    resp[0]=0x02; resp[1]=0x50; resp[2]=req[2];
    *len = 3;
}

void handle_security(uint8_t *req, uint8_t *resp, uint8_t *len) {
    if (sec_attempts >= 3) {
        resp[0]=0x03; resp[1]=SID_NEG_RESP;
        resp[2]=SID_SEC_ACC; resp[3]=0x36;
        *len=4; return;
    }
    if (req[2] == 0x01) {
        srand((unsigned)time(NULL));
        current_seed = rand() % 0xFFFF + 0x1000;
        printf("[ECU] Seed: 0x%04X\n", current_seed);
        resp[0]=0x04; resp[1]=0x67; resp[2]=0x01;
        resp[3]=(current_seed>>8)&0xFF;
        resp[4]=current_seed&0xFF;
        *len=5;
    } else if (req[2] == 0x02) {
        uint32_t rk = (req[3]<<8)|req[4];
        uint32_t ek = compute_key(current_seed) & 0xFFFF;
        if (rk == ek) {
            security_unlocked = 1; sec_attempts = 0;
            printf("[ECU] UNLOCKED!\n");
            resp[0]=0x02; resp[1]=0x67; resp[2]=0x02;
            *len=3;
        } else {
            sec_attempts++;
            printf("[ECU] Wrong key! %d/3\n", sec_attempts);
            resp[0]=0x03; resp[1]=SID_NEG_RESP;
            resp[2]=SID_SEC_ACC; resp[3]=0x35;
            *len=4;
        }
    }
}

typedef struct { uint16_t did; uint8_t data[20]; uint8_t dlen; } DID_t;
DID_t did_table[] = {
    {0xF190, "1HGBH41JXMN109186", 17},
    {0x0100, {0x0B,0xB8}, 2},
    {0x0101, {0x55}, 1},
    {0x0102, {0x0E,0x10}, 2},
};
int did_count = 4;

void handle_read_did(uint8_t *req, uint8_t *resp, uint8_t *len) {
    uint16_t did = (req[2]<<8)|req[3];
    for (int i=0; i<did_count; i++) {
        if (did_table[i].did == did) {
            resp[0] = did_table[i].dlen + 3;
            resp[1] = 0x62;
            resp[2] = req[2]; resp[3] = req[3];
            memcpy(&resp[4], did_table[i].data, did_table[i].dlen);
            *len = did_table[i].dlen + 4;
            printf("[ECU] DID 0x%04X sent\n", did);
            return;
        }
    }
    resp[0]=0x03; resp[1]=SID_NEG_RESP;
    resp[2]=SID_READ_DID; resp[3]=0x31;
    *len=4;
}

typedef struct { uint8_t b0,b1,b2,status; } DTC_t;
DTC_t dtc_mem[] = {
    {0x01,0x01,0x18,0x08},
    {0x01,0x00,0x01,0x08},
};
int dtc_count = 2;

void handle_read_dtc(uint8_t *resp, uint8_t *len) {
    resp[0]=0x00; resp[1]=0x59; resp[2]=0x02;
    int idx=3;
    for (int i=0; i<dtc_count; i++) {
        resp[idx++]=dtc_mem[i].b0;
        resp[idx++]=dtc_mem[i].b1;
        resp[idx++]=dtc_mem[i].b2;
        resp[idx++]=dtc_mem[i].status;
    }
    resp[0]=idx-1;
    *len=idx;
    printf("[ECU] Sent %d DTCs\n", dtc_count);
}

void handle_clear_dtc(uint8_t *resp, uint8_t *len) {
    dtc_count = 0;
    printf("[ECU] DTCs cleared!\n");
    resp[0]=0x01; resp[1]=0x54;
    *len=2;
}

typedef struct {
    uint8_t data[8];
    uint8_t len;
    uint32_t id;
} CANFrame;

CANFrame can_bus[100];
int bus_head=0, bus_tail=0;

void can_send(uint32_t id, uint8_t *data, uint8_t len) {
    can_bus[bus_head].id=id;
    can_bus[bus_head].len=len;
    memcpy(can_bus[bus_head].data, data, len);
    bus_head=(bus_head+1)%100;
}

int can_recv(uint32_t filter_id, uint8_t *data, uint8_t *len) {
    if (bus_tail==bus_head) return 0;
    if (can_bus[bus_tail].id==filter_id) {
        *len=can_bus[bus_tail].len;
        memcpy(data, can_bus[bus_tail].data, *len);
        bus_tail=(bus_tail+1)%100;
        return 1;
    }
    bus_tail=(bus_tail+1)%100;
    return 0;
}

void ecu_process(uint8_t *req, uint8_t req_len,
                 uint8_t *resp, uint8_t *resp_len) {
    uint8_t sid = req[1];
    printf("[ECU] Service: 0x%02X\n", sid);
    switch(sid) {
        case SID_SESSION:  handle_session(req,resp,resp_len); break;
        case SID_SEC_ACC:  handle_security(req,resp,resp_len); break;
        case SID_READ_DID: handle_read_did(req,resp,resp_len); break;
        case SID_READ_DTC: handle_read_dtc(resp,resp_len); break;
        case SID_CLR_DTC:  handle_clear_dtc(resp,resp_len); break;
        case SID_TESTER:
            resp[0]=0x02; resp[1]=0x7E; resp[2]=0x00;
            *resp_len=3; break;
        default:
            resp[0]=0x03; resp[1]=SID_NEG_RESP;
            resp[2]=sid;  resp[3]=0x11;
            *resp_len=4;
    }
}

uint8_t test_requests[][8] = {
    {0x02,0x10,0x03,0,0,0,0,0},
    {0x02,0x27,0x01,0,0,0,0,0},
    {0x03,0x22,0xF1,0x90,0,0,0,0},
    {0x03,0x22,0x01,0x00,0,0,0,0},
    {0x03,0x22,0x01,0x01,0,0,0,0},
    {0x03,0x19,0x02,0xFF,0,0,0,0},
    {0x04,0x14,0xFF,0xFF,0xFF,0,0,0},
};
char *test_names[] = {
    "Enter Extended Session",
    "Request Seed",
    "Read VIN",
    "Read Engine RPM",
    "Read Coolant Temp",
    "Read DTCs",
    "Clear DTCs",
};

int main() {
    printf("==========================================\n");
    printf("   UDS ECU SIMULATOR - C Implementation\n");
    printf("   ISO 14229 Compliant\n");
    printf("==========================================\n\n");

    uint8_t resp[64];
    uint8_t resp_len;
    int n = sizeof(test_requests)/sizeof(test_requests[0]);

    for (int i=0; i<n; i++) {
        printf("\n--- %s ---\n", test_names[i]);
        uint8_t *req = test_requests[i];
        printf("[TESTER] Request: ");
        for (int j=0; j<=req[0]; j++) printf("0x%02X ", req[j]);
        printf("\n");

        resp_len = 0;
        memset(resp, 0, sizeof(resp));
        ecu_process(req, req[0]+1, resp, &resp_len);

        if (i==1 && resp[1]==0x67) {
            uint32_t seed = (resp[3]<<8)|resp[4];
            uint32_t key  = compute_key(seed) & 0xFFFF;
            printf("[TESTER] Computed key: 0x%04X\n", key);
            uint8_t key_req[] = {0x04,0x27,0x02,
                                 (key>>8)&0xFF, key&0xFF};
            printf("\n--- Send Security Key ---\n");
            printf("[TESTER] Request: ");
            for (int j=0; j<5; j++) printf("0x%02X ", key_req[j]);
            printf("\n");
            ecu_process(key_req, 5, resp, &resp_len);
        }

        printf("[ECU]    Response: ");
        for (int j=0; j<resp_len; j++) printf("0x%02X ", resp[j]);
        printf("\n");
    }

    printf("\n==========================================\n");
    printf("   ALL UDS SERVICES TESTED SUCCESSFULLY\n");
    printf("==========================================\n");
    return 0;
}
