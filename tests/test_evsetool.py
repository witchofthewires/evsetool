import pytest
import evsetool
from evsetool import sniffer, wifi_decryptor
from scapy.all import *
import os
from binascii import hexlify

path = os.path.join('tests', 'cap.pcapng')
scapy_cap = rdpcap(path)
for i,p in enumerate(scapy_cap): 
    print(i, p)
    if p.haslayer(sniffer.DstWebSocket): print(p[sniffer.DstWebSocket].frame_data)

def test_websocket_create():
    assert scapy_cap[24].haslayer(sniffer.DstWebSocket)
    output = b'[3,"bad9a3f6-ca80-4901-bb76-9034b8900b5b",{"status":"Accepted","currentTime":"2024-12-12T12:14:42.958Z","interval":14400}]'
    assert scapy_cap[24].frame_data == output

    # make sure zlib state stays good throughout
    output2 = b'[3,"cee3e36b-34fb-45a8-a6b8-f5d394f32beb",{}]'
    assert scapy_cap[42].frame_data == output2

def test_wifi_decryptor_decode_4way_handshake():
    credfile = os.path.join('var', 'wificreds.csv')
    pcap = os.path.join('var', 'capture.pcapng')
    with open(credfile) as fp:
        ssid, password = fp.read().strip().split(',')
    pmk, ptk = wifi_decryptor.main_app(ssid, pcap, password=password)
    assert hexlify(pmk) == b'cb26e56614e866277095b1b861a5e44ecad0c5c6bdaea434374094acec4f6960'
    assert hexlify(ptk) == b'a62ed5b6d903a776fe617d8da7973f86'