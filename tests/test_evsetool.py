import pytest
import evsetool
from evsetool import sniffer
from scapy.all import *
import os

path = os.path.join(os.getcwd(), 'tests/cap.pcapng')
scapy_cap = rdpcap(path)

def test_websocket_create():
    assert scapy_cap[24].haslayer(sniffer.WebSocket)
    output = b'[3,"bad9a3f6-ca80-4901-bb76-9034b8900b5b",{"status":"Accepted","currentTime":"2024-12-12T12:14:42.958Z","interval":14400}]'
    assert scapy_cap[24].frame_data == output

