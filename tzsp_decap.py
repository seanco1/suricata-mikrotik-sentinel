import socket
import os

# Listen for TZSP packets from MikroTik on UDP port 37008
raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
tzsp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tzsp_sock.bind(('0.0.0.0', 37008))

# Raw socket to inject decapsulated Ethernet frame into br-ids
inject_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
inject_sock.bind(('br-ids', 0))

print("Listening for MikroTik TZSP streams on UDP 37008 and decapsulating into br-ids...")
while True:
    data, addr = tzsp_sock.recvfrom(65535)
    # Check TZSP header (version 1, type 0 = received packet)
    if len(data) > 5 and data[0] == 1:
        # Skip TZSP header fields until field type 0x01 (packet payload) or end marker 0xFF
        idx = 4
        while idx < len(data):
            tag = data[idx]
            if tag == 0x01: # Ethernet packet tag
                payload = data[idx+1:]
                try:
                    inject_sock.send(payload)
                except OSError as e:
                    pass
                break
            elif tag == 0xFF: # End of header
                payload = data[idx+1:]
                try:
                    inject_sock.send(payload)
                except OSError as e:
                    pass
                break
            elif tag == 0x00: # Padding
                idx += 1
            else:
                length = data[idx+1] if idx+1 < len(data) else 0
                idx += 2 + length
