import can, time

TESTER_ID = 0x7DF
ECU_ID = 0x7E8
bus = can.Bus(interface='virtual', channel='test')

def send_uds(data):
    bus.send(can.Message(arbitration_id=TESTER_ID, data=data, is_extended_id=False))
    print("[TESTER] Sent: " + str([hex(b) for b in data]))
    resp = bus.recv(timeout=2.0)
    if resp and resp.arbitration_id == ECU_ID:
        print("[ECU]    Reply: " + str([hex(b) for b in resp.data]))
        return list(resp.data)
    print("[TESTER] No response!")
    return None

print("="*40)
print("DIAGNOSTIC SESSION STARTED")
print("="*40)
print("Step 1: Enter Session")
send_uds([0x02, 0x10, 0x03])
time.sleep(0.3)
print("Step 2: Request Seed")
resp = send_uds([0x02, 0x27, 0x01])
time.sleep(0.3)
if resp and len(resp) >= 5 and resp[1] == 0x67:
    seed = (resp[3]<<8)|resp[4]
    key = (seed ^ 0xA5A5A5A5 + 0x1234) & 0xFFFF
    print("Step 3: Send Key " + hex(key))
    send_uds([0x04, 0x27, 0x02, (key>>8)&0xFF, key&0xFF])
    time.sleep(0.3)
print("Step 4: Read VIN")
send_uds([0x03, 0x22, 0xF1, 0x90])
time.sleep(0.3)
print("Step 5: Read RPM")
send_uds([0x03, 0x22, 0x01, 0x00])
time.sleep(0.3)
print("Step 6: Read DTCs")
send_uds([0x03, 0x19, 0x02, 0xFF])
time.sleep(0.3)
print("Step 7: Clear DTCs")
send_uds([0x04, 0x14, 0xFF, 0xFF, 0xFF])
time.sleep(0.3)
print("="*40)
print("SESSION COMPLETE!")
print("="*40)
bus.shutdown()
