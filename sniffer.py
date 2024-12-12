#!/usr/bin/env python
from scapy.all import sniff
from scapy.packet import *
from scapy.fields import *
from scapy.layers import http
from scapy.layers.inet import TCP
import re
import datetime
import array
import zlib
from websockets import frames

http.COMMON_UNSTANDARD_REQUEST_HEADERS.append('Sec-WebSocket-Key')

UPGRADE_REGEX = re.compile(r"Upgrade: websocket")
WS_KEY_REGEX = re.compile(r"Sec-WebSocket-Key: (\S+)")

# TODO combine files
def log(msg):
    print("[*] %s - %s" % (rightnow(), msg))

def rightnow():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def decode(
    frame,
    *,
    max_size: int | None = None,
)  -> frames.Frame:
    """
    Decode an incoming frame.

    """
    print("entered")
    # Skip control frames.
    if frame.opcode >= 0xb:
        return frame
    print('past1')
    print("%d flags: %s, %s" % (frame.flags, frame.flags, type(frame)))
    # Handle continuation data frames:
    # - skip if the message isn't encoded
    # - reset "decode continuation data" flag if it's a final frame
    if frame.opcode == 0:
        print('in it now')
        if not self.decode_cont_data:
            return frame
        if frame.flags[3]:
            self.decode_cont_data = False

    # Handle text and binary data frames:
    # - skip if the message isn't encoded
    # - unset the rsv1 flag on the first frame of a compressed message
    # - set "decode continuation data" flag if it's a non-final frame
    else:
        if not frame.flags[2]:
            return frame
        if not frame.flags[3]:
            self.decode_cont_data = True

        # Re-initialize per-message decoder.
        if self.remote_no_context_takeover:
            self.decoder = zlib.decompressobj(wbits=-self.remote_max_window_bits)
    print('past2')

    # Uncompress data. Protect against zip bombs by preventing zlib from
    # decompressing more than max_length bytes (except when the limit is
    # disabled with max_size = None).
    if frame.flags[2] and len(frame.frame_data) < 2044:
        # Profiling shows that appending four bytes, which makes a copy, is
        # faster than calling decompress() again when data is less than 2kB.
        data = bytes(frame.frame_data) + b"\x00\x00\xff\xff"
    else:
        data = frame.frame_data
    max_length = 0 if max_size is None else max_size
    try:
        print("INPUT: %s %d" % (data, max_length))
        data = self.decoder.decompress(data, max_length)
        print("OUTPUT: %s" % data)
        if self.decoder.unconsumed_tail:
            assert max_size is not None  # help mypy
            raise Exception("Payload too big!!!")
        if frame.flags[3] and len(frame.frame_data) >= 2044:
            # This cannot generate additional data.
            self.decoder.decompress(b"\x00\x00\xff\xff")
    except zlib.error as exc:
        raise ProtocolError("decompression failed") from exc

    # Allow garbage collection of the decoder if it won't be reused.
    if frame.flags[3] and self.remote_no_context_takeover:
        del self.decoder

    return frames.Frame(
        frame.opcode,
        data,
        frame.fin,
        # Unset the rsv1 flag on the first frame of a compressed message.
        False,
        frame.rsv2,
        frame.rsv3,
    )

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
    if 'HTTP' in payload: return http.HTTPRequest
    elif isinstance(self.underlayer, TCP):
      return WebSocket
    else:
      return Packet.guess_payload_class(self, payload)
  
  def post_dissection(self, pkt):
    #print('up top ', type(pkt[WebSocket]), pkt[WebSocket])
    pkt = pkt[WebSocket] # TODO rewrite func remove this
    if(pkt.mask_flag == 1 and pkt.frame_data is not None):
      demask = array.array('I', [pkt.mask >> 24 & 0xff, pkt.mask >> 16 & 0xff, pkt.mask >> 8 & 0xff, pkt.mask & 0xff])
      unmasked = ''
      print("\tBEFORE: %s" % pkt.frame_data)
      for i, c in enumerate(pkt.frame_data):
        unmasked += chr(c ^ (demask[i % 4]))
      pkt.frame_data = unmasked
      print("\tAFTER: %s" % pkt.frame_data)
      #print('before')
      #print('here')
    #print('done')
    try:
      #print('inside ', pkt.frame_data)
      d = zlib.decompressobj(wbits=-15)
      pkt.frame_data = d.decompress(pkt.frame_data + b"\x00\x00\xff\xff")
      #print(pkt.frame_data) 
      #if isinstance(pkt, WebSocket):
      #    pkt.frame_data = decode(pkt)
    except Exception as e:
      print(e)
    return pkt

bind_layers(TCP, WebSocket, dport=8180)
bind_layers(TCP, WebSocket, sport=8180)

def parse(pkt):
    print('----------------------------------------------------------')
    ws_str = "WebSocket" if pkt.haslayer(WebSocket) else ""
    print(pkt.sprintf("Sniffed message: %IP.src%:%IP.sport%->%IP.dst%:%IP.dport%\t" + ws_str))
    if ws_str != "": print('\t%s' % pkt[WebSocket].frame_data)
    http_str = ""
    if pkt.haslayer(Raw):
        if b'HTTP' in pkt[Raw].load: 
            print('\t%s' % http.HTTPRequest(pkt[Raw].load))
    print('----------------------------------------------------------')

def main():
    sniff(iface="lo", filter="port 8180", prn=parse, store=False)

if __name__ == '__main__':
    main()
