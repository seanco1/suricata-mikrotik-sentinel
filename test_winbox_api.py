import socket
import struct

# Simple check for WinBox / RouterOS API ports
for port in [8291, 8728, 8729, 443, 80, 22]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    res = s.connect_ex(('172.18.141.1', port))
    s.close()
    print(f"Port {port}: {'OPEN' if res == 0 else 'CLOSED/TIMED OUT'}")
