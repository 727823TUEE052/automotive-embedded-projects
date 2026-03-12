import can, random

ECU_RECV_ID = 0x7DF
ECU_SEND_ID = 0x7E8
security_attempts = 0
current_seed = 0
security_unlocked = False

ecu_data = {
    0xF190: b'1HGBH41JXMN109186',
    0x0100: bytes([0x0B, 0xB8]),
    0x0101: bytes([0x55]),
}
dtcs = [[0x01, 0x01, 0x18, 0x08], [0x01, 0x00, 0x01, 0x08]]

def compute_key(seed):
    return (seed ^ 0xA5A5A5A5 + 0x1234) & 0xFFFF

def handle(data):
    global security_attempts, current_seed, security_unlocked
    sid = data[1]
    print("[ECU] Service: " + hex(sid))
    if sid == 0x10:
        return [0x02, 0x50, data[2]]
    elif sid == 0x27:
        if security_attempts >= 3:
            return [0x03, 0x7F, 0x27, 0x36]
        if data[2] == 0x01:
            current_seed = random.randint(0x1000, 0xFFFF)
            return [0x04, 0x67, 0x01, (current_seed>>8)&0xFF, current_seed&0xFF]
        elif data[2] == 0x02:
            rk = (data[3]<<8)|data[4]
            ek = compute_key(current_seed)
            if rk == ek:
                security_unlocked = True
                print("[ECU] UNLOCKED!")
                return [0x02, 0x67, 0x02]
            security_attempts += 1
            return [0x03, 0x7F, 0x27, 0x35]
    elif sid == 0x22:
        did = (data[2]<<8)|data[3]
        if did in ecu_data:
            v = ecu_data[did]
            return [len(v)+3, 0x62, data[2], data[3]] + list(v)
        return [0x03, 0x7F, 0x22, 0x31]
    elif sid == 0x19:
        r = [0x00, 0x59, 0x02]
        for d in dtcs:
            r.extend(d)
        r[0] = len(r)-1
        return r
    elif sid == 0x14:
        dtcs.clear()
        print("[ECU] DTCs cleared!")
        return [0x01, 0x54]
    return [0x03, 0x7F, sid, 0x11]

bus = can.Bus(interface='virtual', channel='test')
print("="*40)
print("  ECU STARTED - Listening...")
print("="*40)
while True:
    msg = bus.recv(timeout=1.0)
    if msg and msg.arbitration_id == ECU_RECV_ID:
        resp = handle(list(msg.data))
        if resp:
            bus.send(can.Message(arbitration_id=ECU_SEND_ID, data=resp, is_extended_id=False))
            print("[ECU] Reply: " + str([hex(b) for b in resp]))
