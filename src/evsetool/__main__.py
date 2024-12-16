import argparse
import logging
import asyncio

import yaml

from .sniffer import parse, main as sniff
from .evse import simflow_transaction

parser = argparse.ArgumentParser(description='EVSE Red Team Tool')
parser.add_argument('-v', '--verbose', action='store_true',
                help='Show full OCPP traffic output')
parser.add_argument('-f', '--file', type=str,
                help='Path to YAML configuration file')
parser.add_argument('--sniff', action='store_true',
                help='Listen passively for OCPP1.6 traffic over TCP 8180')
parser.add_argument('--evse', action="store_true",
                help='Interact with EVSE in role of CSMS')
parser.add_argument('--csms', action='store_true',
                help='Interact with CSMS in role of EVSE')
parser.add_argument('--url', type=str,
                help='Address of CSMS to query')
parser.add_argument('-i', '--id', type=str,
                help='20-character string uniquely identifying the EVSE')
parser.add_argument('--vendor', type=str, default='WitchWires',
                help='Company which produced the EVSE')
parser.add_argument('--model', type=str, default='WW1959',
                help='Name of the specific model of EVSE')
parser.add_argument('--name', type=str, default='CP_1',
                help='API endpoint for the EVSE')
parser.add_argument('--pcap', type=str,
                help='Read from a PCAP rather than sniffing LAN')

args = parser.parse_args()

args.file = './default.config.yaml' if not args.file else args.file
with open(args.file) as f:
    cfg = yaml.load(f, Loader=yaml.FullLoader)
                    
url = cfg['csms'] if args.url is None else args.url
id_tag = cfg['id_tag'] if args.id is None else args.id
log_level = logging.INFO if args.verbose else logging.ERROR
logging.basicConfig(level=log_level)
args = parser.parse_args()

if args.sniff:
    print("Starting sniffer...")
    sniff()
elif args.pcap:
    print("Reading pcap <%s>..." % args.pcap)
    pkt = rdpcap(args.pcap)
    for p in map(parse, pkt): 
        if p is not None: print(p)         
elif args.csms:
    print("Querying CSMS...")
    asyncio.run(simflow_transaction(url, id_tag, args.name))
else:
    print("ERROR: Please select one of the following: [sniff|pcap|csms]")
    print("use --help for more information")
