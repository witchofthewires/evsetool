import argparse
import logging
import asyncio
import yaml
from scapy.all import rdpcap
import time

from sniffer import parse, main as sniff
from evse import simflow_transaction, simflow_diagnostics
from csms import serve_OCPPv16
from utils import *

async def main():

    parser = argparse.ArgumentParser(description='EVSE Red Team Tool')
    parser.add_argument('-v', '--verbose', action='store_true',
                    help='Show full OCPP traffic output')
    parser.add_argument('-f', '--file', type=str,
                    help='Path to YAML configuration file')
    parser.add_argument('--sniff', action='store_true',
                    help='Listen passively for OCPP1.6 traffic over TCP 8180')
    parser.add_argument('--serve', action="store_true",
                    help='Serves OCPP1.6 on $local_ocpp_port')
    parser.add_argument('--csms', action='store_true',
                    help='Interact with CSMS in role of EVSE')
    parser.add_argument('--sim', action='store_true',
                    help='Simulate dialogue between EVSE and CSMS')
    parser.add_argument('--url', type=str,
                    help='Address of system to query')
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
                        
    url = cfg['url'] if args.url is None else args.url
    id_tag = cfg['id_tag'] if args.id is None else args.id
    log_level = logging.INFO if args.verbose else logging.ERROR
    logging.basicConfig(level=log_level)
    args = parser.parse_args()

    if args.sniff:
        log("EVSETOOL::Starting sniffer...")
        sniff()
    elif args.pcap:
        log("EVSETOOL::Reading pcap <%s>..." % args.pcap)
        pkt = rdpcap(args.pcap)
        for p in map(parse, pkt): 
            if p is not None: print(p)         
    elif args.csms:
        log("EVSETOOL::Querying CSMS...")
        asyncio.run(simflow_transaction(url, id_tag, args.name))
    elif args.serve:
        log("EVSETOOL::Serving OCPP1.6 on port %d" % cfg['local_ocpp_port'])
        asyncio.run(serve_OCPPv16('0.0.0.0', cfg['local_ocpp_port']))
    elif args.sim:
        log("EVSETOOL::Running sim_diagnostics")
        ip_addr = '127.0.0.1'
        port = cfg['local_ocpp_port']
        await run_sim(ip_addr, port, id_tag, args.name)
        #sniff()
    else:
        print("ERROR: Please select one of the following: [csms|sim|sniff|pcap|]")
        print("use --help for more information")

async def run_sim(ip_addr, port, id_tag, name):
    log('ere')
    server_url = 'ws://%s:%s' % (ip_addr, port)
    
    loop = asyncio.get_running_loop()
    loop.create_task(serve_OCPPv16(ip_addr, port))
    loop.create_task(simflow_diagnostics(server_url, id_tag, name))

if __name__ == '__main__':
    asyncio.run(main())