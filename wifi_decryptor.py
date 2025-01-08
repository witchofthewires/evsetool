# -*- coding: utf-8 -*-
from scapy.all import rdpcap, EAPOL, Dot11, Raw, EAPOL_KEY
from binascii import hexlify, a2b_hex
from hashlib import pbkdf2_hmac, sha1
from hmac import new
from itertools import product
from functools import partial
from time import time
import os
from os import cpu_count
from multiprocessing import Pool
from copy import deepcopy as copy

def check(pkt, handshakes, bssid, client_mac):
    
    f_nonce = b'00'*32
    f_mic = b'00'*16
    
    if pkt.haslayer(EAPOL):

        __sn = pkt[Dot11].addr2
        __rc = pkt[Dot11].addr1
        to_DS = pkt.getlayer(Dot11).FCfield & 0x1 != 0
        from_DS = pkt.getlayer(Dot11).FCfield & 0x2 != 0

        if from_DS:
            nonce = hexlify(getattr(pkt[EAPOL_KEY], 'key_nonce'))
            mic = hexlify(getattr(pkt[EAPOL_KEY], 'key_mic'))
            if nonce != f_nonce and mic == f_mic:
                bssid = __sn
                client_mac = __rc
                handshakes[0] = pkt
            elif (__sn == bssid and __rc == client_mac and
                    nonce != f_nonce and mic != f_mic):
                handshakes[2] = pkt
        elif to_DS:
            nonce = hexlify(getattr(pkt[EAPOL_KEY], 'key_nonce'))
            mic = hexlify(getattr(pkt[EAPOL_KEY], 'key_mic'))
            if (__sn == client_mac and 
                __rc == bssid and
                nonce != f_nonce and 
                mic != f_mic):
                handshakes[1] = pkt
            elif (__sn == client_mac and 
                  __rc == bssid and
                  nonce == f_nonce and 
                  mic != f_mic):
                handshakes[3] = pkt

    return bssid, client_mac


def organize(bssid, client_mac, handshakes):
    bssid = a2b_hex(bssid.replace(':', '').lower())
    client_mac = a2b_hex(client_mac.replace(':', '').lower())
    a_nonce = a2b_hex(hexlify(getattr(handshakes[0][EAPOL_KEY], 'key_nonce')))
    s_nonce = a2b_hex(hexlify(getattr(handshakes[1][EAPOL_KEY], 'key_nonce')))
    key_data = (min(bssid, client_mac) + max(bssid, client_mac) +
                min(a_nonce, s_nonce) + max(a_nonce, s_nonce))
    mic = hexlify(getattr(handshakes[1][EAPOL_KEY], 'key_mic'))
    payload = copy(handshakes[1])
    setattr(payload, 'key_mic', '\x00' * 16)
    return key_data, mic, payload[EAPOL].build()


def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)//160):
        hmacsha1 = new(key, (A + b'\x00' + B + bytes([i])), sha1)
        i += 1
        R += hmacsha1.digest()
    return R[:blen]


def try_password(password, essid, key_data, payload, mic, length):
    pmk = pbkdf2_hmac('sha1', password.encode(), essid.encode(), 4096, 32)
    ptk = customPRF512(pmk, b"Pairwise key expansion", key_data)
    print(hexlify(ptk))
    _mic = new(ptk[0:16], payload, sha1).hexdigest()[:32].encode()
    result = password if mic == _mic else None 
    return result


def main_app(essid, file_with_packets, s=None, l=None, password=None):
    cpu_num = cpu_count()
    print(' * Number of CPUs: ', cpu_num, '\n')
    packets = rdpcap(file_with_packets)
    handshakes = [0, 0, 0, 0]
    essid = essid
    bssid = ''
    client_mac = ''

    LATIN_LOWER = 'abcdefghijklmnopqrstuvwxyz'
    LATIN_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    NUMBERS = '0123456789'
    CUSTOM = 'abcdef'

    if password is not None:
        print("Using password %s" % password)
        passwords = tuple([password])
        length = 1
    else:
        if chars is not None and l is not None:
            characters = chars
            rep = l
        else:
            characters = CUSTOM            # The characters of the password
            rep = 5                        # The length of the password

        length = len(characters)**rep  # The numbers of passwords to be generated

        print(f" * {length} passwords will be generated\n")

        words = product(characters, repeat=rep)
        passwords = []
        for i, pwd in enumerate(words):
            passwords.append((i, pwd))
        passwords = tuple(passwords)

    for pkt in packets:
        bssid, client_mac = check(pkt, handshakes, bssid, client_mac)

    if all(handshakes):
        print(" * The packets were successfully checked\n")
    else:
        print("Failed to recover all pieces of handshake")
        print(handshake)
        return

    key_data, mic, payload = organize(bssid, client_mac, handshakes)
    result = try_password(password, essid, key_data, payload, mic, length)
    if result is not None:
        print("Cracked password: %s" % result)
    else:
        print("Failed to crack password")
    '''
    loop_func = partial(try_password, essid=essid,
                        key_data=key_data, payload=payload,
                        mic=mic, length=length)

    start = time()
    pool = Pool(processes=cpu_num)
    results = []
    try:
        for result in pool.imap_unordered(loop_func, passwords):
            if result:
                results.append(result)
                pool.terminate()
                break
    finally:
        pool.close()
        pool.join()

    end = time() - start
    print(f"It has taken {int(end)} seconds")
    '''

if __name__ == "__main__":
    with open(os.path.join('var', 'wificreds.csv')) as fp:
        ssid, password = fp.read().strip().split(',')
    main_app(ssid, "capture.pcapng", password=password)