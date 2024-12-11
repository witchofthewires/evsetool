#!/usr/bin/env python
from scapy.all import sniff
from scapy.packet import *
from scapy.fields import *
from scapy.layers import http
from scapy.layers.inet import TCP
import re
import datetime
import array

http.COMMON_UNSTANDARD_REQUEST_HEADERS.append('Sec-WebSocket-Key')

UPGRADE_REGEX = re.compile(r"Upgrade: websocket")
WS_KEY_REGEX = re.compile(r"Sec-WebSocket-Key: (\S+)")

# TODO combine files
def log(msg):
    print("[*] %s - %s" % (rightnow(), msg))

def rightnow():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

# RFC6455 section 5.2
_ws_opcode_names = {
    0 : "continuation_frame",
    1 : "text_frame",
    2 : "binary_frame",
    3 : "reserved_non_control3",
    4 : "reserved_non_control4",
    5 : "reserved_non_control5",
    6 : "reserved_non_control6",
    7 : "reserved_non_control7",
    8 : "connection_close",
    9 : "ping",
  0xa : "pong",
  0xb : "reserved_controlB",
  0xc : "reserved_controlC",
  0xd : "reserved_controlD",
  0xe : "reserved_controlE",
  0xf : "reserved_controlF"
}

class WebSocket(Packet):
  name = "WebSocket"
  fields_desc = [ FlagsField("flags", 0, 4, ["RSV3", "RSV2", "RSV1", "FIN"]),
                  BitEnumField("opcode", 0, 4, _ws_opcode_names),
                  BitField("mask_flag", 0, 1),
                  BitField("length", 0, 7),
                  ConditionalField(BitField("length16", None, 16), lambda pkt:pkt.length == 126),
                  ConditionalField(BitField("length64", None, 64), lambda pkt:pkt.length == 127),
                  ConditionalField(XIntField("mask", 0), lambda pkt:pkt.mask_flag == 1),
                  StrLenField("frame_data", None,
                              length_from=lambda pkt:(pkt.length64 if pkt.length64 else
                                                      pkt.length16 if pkt.length16 else
                                                      pkt.length))
                ]
  

  def guess_payload_class(self, payload):
    #print("entered")
    if 'HTTP' in payload: return http.HTTPRequest
    elif isinstance(self.underlayer, TCP):
      #print("got here")
      return WebSocket
    else:
      return Packet.guess_payload_class(self, payload)

  def post_dissection(self, pkt):
    if(pkt.mask_flag == 1 and pkt.frame_data is not None):
      #print('here <%x>' % pkt.mask)
      #print('watch this')
      demask_array = [pkt.mask >> 24 & 0xff, pkt.mask >> 16 & 0xff, pkt.mask >> 8 & 0xff, pkt.mask & 0xff]
      #print('got it')
      #print(demask_array)
      demask = array.array('I', demask_array)
      #print('there')
      unmasked = ''
      #print('where')
      for i, c in enumerate(pkt.frame_data):
        #print(i, c)
        #print(type(i), type(c))
        #x = ord(c)
        #print('then')
        #print('now')
        unmasked += chr(c ^ (demask[i % 4]))
        #print(res)
        #print('gottem')
        #print(unmasked)
        #print('oops')
      #print('everywhere')
      pkt.frame_data = unmasked
      print('succ: %s' % unmasked)
      return pkt
    else:
      print('fail')
      pass

#bind_layers(TCP, http.HTTPRequest, dport=8180)
bind_layers(TCP, WebSocket, dport=8180)

def parse(pkt): return pkt.show()
def parse2(pkt): 
    raw = "ajsv" if not pkt.haslayer(Raw) else pkt[Raw]
    return pkt.sprintf("%IP.src% -> %IP.dst%")
def ws_parse(pkt):
    if Raw in pkt: log(pkt[Raw].show())
    #return WebSocket(bytes(pkt)).show()

def detect_http_get(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        http_data = packet[Raw].load.decode('utf-8', 'ignore')
        if "GET" in http_data:
            if UPGRADE_REGEX.findall(http_data):
                key = WS_KEY_REGEX.findall(http_data)[0]
                log("Sniffed websocket key %s" % key)

def main():
    sniff(iface="lo", filter="port 8180", prn=parse, store=False)

if __name__ == '__main__':
    main()
