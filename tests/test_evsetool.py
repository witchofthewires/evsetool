import pytest
import evsetool
from evsetool import sniffer
from scapy.all import *
import os

path = os.path.join(os.getcwd(), 'tests/cap.pcapng')
scapy_cap = rdpcap(path)
for i,p in enumerate(scapy_cap): 
    print(i, p)
    if p.haslayer(sniffer.WebSocket): print(p[sniffer.WebSocket].frame_data)

def test_websocket_create():
    assert scapy_cap[24].haslayer(sniffer.WebSocket)
    output = b'[3,"bad9a3f6-ca80-4901-bb76-9034b8900b5b",{"status":"Accepted","currentTime":"2024-12-12T12:14:42.958Z","interval":14400}]'
    assert scapy_cap[24].frame_data == output

    # make sure zlib state stays good throughout
    output2 = b'[3,"cee3e36b-34fb-45a8-a6b8-f5d394f32beb",{}]'
    assert scapy_cap[42].frame_data == output2
