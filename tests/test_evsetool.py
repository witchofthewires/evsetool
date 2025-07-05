import pytest
import evsetool
from evsetool import sniffer, wifi_decryptor
from scapy.all import *
import os
from binascii import hexlify

aes_key = bytes.fromhex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
nonce = bytes.fromhex("00000003020100A0A1A2A3A4A5")
input_data = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
output_data = bytes.fromhex("0001020304050607588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0")
CCMPContext = wifi_decryptor.CCMPContext



pkt50_aes_key = bytes.fromhex("a62ed5b6d903a776fe617d8da7973f86")
pkt50_nonce = b'\x00' * 7 + b'\x09'
pkt50_input_data = bytes.fromhex("aaaa0300000008060001080006040001d83addeffe9ec0a800b1000000000000c0a80001")
pkt50_output_data = bytes.fromhex("c1efe894f6939eb71c526e68f6ee6a907fba530381d7d61b4f45d2c9a847bd45368b91c81b48a88331de05fe")

def prep_websocket_tests():
    
    path = os.path.join('tests', 'cap.pcapng')
    scapy_cap = rdpcap(path)
    
    # TODO can this be removed
    for i,p in enumerate(scapy_cap): 
        print(i, p)
        if p.haslayer(sniffer.DstWebSocket): print(p[sniffer.DstWebSocket].frame_data)
    
    return scapy_cap

def prep_wifi_tests():
    pcap = os.path.join('var', 'capture.pcapng')
    credfile = os.path.join('var', 'wificreds.csv')
    with open(credfile) as fp:
        ssid, password = fp.read().strip().split(',')
    return pcap, ssid, password

# make sure zlib state stays good throughout
def test_zlib_state():
    cap = prep_websocket_tests()
    output = b'[3,"cee3e36b-34fb-45a8-a6b8-f5d394f32beb",{}]'
    assert cap[42].frame_data == output 

def test_websocket_create():
    cap = prep_websocket_tests()
    assert cap[24].haslayer(sniffer.DstWebSocket)
    output = b'[3,"bad9a3f6-ca80-4901-bb76-9034b8900b5b",{"status":"Accepted","currentTime":"2024-12-12T12:14:42.958Z","interval":14400}]'
    assert cap[24].frame_data == output

'''
def test_wifi_decryptor_decode_4way_handshake():
    pcap, ssid, password = prep_wifi_tests()
    pmk, ptk = wifi_decryptor.main_app(ssid, pcap, password=password)
    assert hexlify(pmk) == b'cb26e56614e866277095b1b861a5e44ecad0c5c6bdaea434374094acec4f6960'
    assert hexlify(ptk) == b'a62ed5b6d903a776fe617d8da7973f86'

# TODO can first two lines here be combined with previous
def test_wifi_decryptor_ccm_decryption():
    pcap, ssid, password = prep_wifi_tests()
    pmk, ptk = wifi_decryptor.main_app(ssid, pcap, password=password)
    packet = rdpcap(pcap)[49]
    ctext = getattr(packet[Dot11CCMP], 'data')
    assert hexlify(ctext) == hexlify(pkt50_output_data)
    ptext = wifi_decryptor.decrypt_packet(packet, ptk)
    print(len(ctext), len(ptext))
    assert hexlify(ptext) == b'aaaa0300000008060001080006040001d83addeffe9ec0a800b1000000000000c0a80001'
'''
def test_ccm_encrypt_rfc3610_testvector1():
    ccmp = CCMPContext(input_data, aes_key, nonce, decrypt=False)
    ctext, mac = wifi_decryptor.aes_ccm_encrypt(ccmp.key, ccmp.nonce, ccmp.ptext, ccmp.aad)
    print(ccmp.__print__())
    result = ccmp.aad + ctext + mac
    assert hexlify(result) == hexlify(output_data)
'''
def test_ccm_decrypt_capture_pkt50():
    mpkt50_output_data = bytes.fromhex('0001020304050607') + pkt50_output_data
    ccmp = CCMPContext(mpkt50_output_data, pkt50_aes_key, pkt50_nonce, decrypt=True)
    #ccmp.aad = pkt50_output_data[:8]
    #ccmp.aad = bytes.fromhex('aaaa030000000806')
    ptext = wifi_decryptor.aes_ccm_decrypt(ccmp.key, ccmp.nonce, ccmp.ctext, ccmp.aad, ccmp.mac)
    print(ccmp.__print__())
    result = ccmp.aad + ptext
    print(hexlify(result))
    print(hexlify(pkt50_input_data))
    assert hexlify(result) == hexlify(pkt50_input_data)
'''
def test_ccm_decrypt_rfc3610_testvector1():
    ccmp = CCMPContext(output_data, aes_key, nonce, decrypt=True)
    _ptext = wifi_decryptor.aes_ccm_decrypt(ccmp.key, ccmp.nonce, ccmp.ctext, ccmp.aad, ccmp.mac)
    print(ccmp.__print__())
    assert hexlify(input_data[8:]) == hexlify(_ptext)
