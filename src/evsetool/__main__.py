import argparse
import logging
import asyncio
import yaml
import scapy
import time
import websockets
import multiprocessing 

from .sniffer import main as sniffer_main
from .evse import simflow_transaction, simflow_diagnostics
from .csms import serve_OCPPv16
from .utils import *

DEFAULT_ID_TAG = "01234567890123456789"
DEFAULT_URL = "ws://127.0.0.1:8180/steve/websocket/CentralSystemService"
DEFAULT_LOCAL_OCPP_PORT = 9000

async def main():
    parser = argparse.ArgumentParser(description='EVSE Red Team Tool')
    parser.add_argument('-v', '--verbose', action='store_true',
                    help='Show full OCPP traffic output')
    parser.add_argument('-vv', '--verbose-debug', action='store_true',
                    help='Show debug logs')
    parser.add_argument('-f', '--file', type=str,
                    help='Path to YAML configuration file')
    parser.add_argument('--sniff', action='store_true',
                    help='Listen passively for OCPP1.6 traffic over TCP 8180')
    parser.add_argument('--log_sniffed', action='store_true',
                    help='If true, sniffed traffic is passed to logging handler; if false, sent directly to stdout')
    parser.add_argument('--serve', action="store_true",
                    help='Serves OCPP1.6 on $local_ocpp_port')
    parser.add_argument('--query', action='store_true',
                    help='Interact with CSMS in role of EVSE')
    parser.add_argument('--url', type=str,
                    help='Address of system to query')
    parser.add_argument('-e', '--evse_id', type=str,
                    help='20-character string uniquely identifying the EVSE')
    parser.add_argument('--vendor', type=str, default='WitchWires',
                    help='Company which produced the EVSE')
    parser.add_argument('--model', type=str, default='WW1959',
                    help='Name of the specific model of EVSE')
    parser.add_argument('--name', type=str, default='CP_1',
                    help='API endpoint for the EVSE')
    parser.add_argument('--pcap', type=str,
                    help='Read from a PCAP rather than sniffing LAN')
    parser.add_argument('--sim', action='store_true',
                    help='Simulate')
    parser.add_argument('-i', '--interactive', action='store_true',
                    help='Interactive execution mode')
    args = parser.parse_args()

    url = DEFAULT_URL
    id_tag = DEFAULT_ID_TAG
    local_ocpp_port = DEFAULT_LOCAL_OCPP_PORT
    args.file = './default.config.yaml' if not args.file else args.file
    try:
        with open(args.file) as f:
            cfg = yaml.load(f, Loader=yaml.FullLoader)
            url = cfg['url'] if args.url is None else args.url
            id_tag = cfg['id_tag'] if args.evse_id is None else args.evse_id
            local_ocpp_port = cfg['local_ocpp_port'] # TODO add command-line option
    except FileNotFoundError:            
        pass

    log_level = logging.ERROR
    if args.verbose_debug: log_level = logging.DEBUG
    elif args.verbose: log_level = logging.INFO

    global logger
    logger = logging_setup(__name__, log_level=log_level)
    logger.info(f"Initialized logger '{__name__}'")
    args = parser.parse_args()
    for k, v in args.__dict__.items():
        logger.debug(f"Argument '{k}': '{v}'")


    log_sniffed = False if not args.log_sniffed else True
    if args.sniff: sniff(log_sniffed)
    elif args.pcap: pcap(args.pcap) 
    elif args.query: await query(url, id_tag, args.name)
    elif args.serve: await serve(local_ocpp_port)
    elif args.sim:
        logger.info("EVSETOOL::Running sim_diagnostics")
        ip_addr = '127.0.0.1'
        port = local_ocpp_port
        await run_sim(ip_addr, port, id_tag, args.name)
        #sniffer_main()
    elif args.interactive:
        logger.info("EVSETOOL::Entering interactive mode")
        await interactive()
    else:
        print("ERROR: Please select one of the following: [query|sim|sniff|pcap|interactive]")
        print("use --help for more information")

async def interactive():
    while True:
        user_input = input("evsetool> ")
        user_fields = user_input.split(' ')
        match user_fields[0]:
            case "query": 
                try:
                    url = user_fields[1]
                    id_tag = user_fields[2]
                    evse_name = user_fields[3]
                    await query(url, id_tag, evse_name)
                except IndexError:
                    print("query command requires inputs url, id_tag and evse_name")
                    print("Type 'help' to see a list of possible commands and their inputs")
            case "serve": 
                try:
                    lport = int(user_fields[1])
                    await serve(lport)
                except (IndexError, ValueError):
                    print("serve command requires integer input lport")
                    print("Type 'help' to see a list of possible commands and their inputs")
            case "sim": 
                #sim()
                pass
            case "sniff":
                sniff()
            case "pcap":
                try:
                    filename = user_fields[1]
                    pcap(filename)
                except IndexError:
                    print("pcap command requires input filename")
                    print("Type 'help' to see a list of possible commands and their inputs")
                except FileNotFoundError:
                    print(f"Failed to open file '{filename}': file not found")
            case "q":
                return
            case "quit":
                return
            case "exit":
                return
            case "help": 
                interactive_help()
            case _: 
                print("Invalid input.\n")
                interactive_help()

def interactive_help():
    print("COMMANDS\n--------")
    print("query URL ID_TAG EVSE_NAME\n\tquery remote OCPP1.6 server")
    print("serve LPORT\n\tserve OCPP1.6 traffic on local port")
    print("sim\n\tWIP simulation mode")
    print("sniff\n\tlistens on the LAN for OCPP1.6 traffic")
    print("pcap FILENAME\n\tparse pcap, pcapng input file")
    print("quit (or q, or exit)\n\texit interactive shell")
    print("help\n\tdisplay this help message")
    print()

async def query(url, id_tag, name):
    logger.info(f"Querying '{url}' with id_tag '{id_tag}' and evse_name '{name}'")
    try:
        await simflow_transaction(url, id_tag, name)
    except websockets.exceptions.InvalidStatus as e:
        logger.error(f'Query failed: {e}')

def pcap(filename):
    logger.info(f"EVSETOOL::Reading pcap '{filename}'")
    pkt = scapy.all.rdpcap(filename)
    for p in map(parse, pkt): 
        if p is not None: print(p)        

async def run_sim(ip_addr, port, id_tag, name):
    logger.info('Initiating simulation')
    server_url = 'ws://%s:%s' % (ip_addr, port)
    loop = asyncio.get_running_loop()
    loop.create_task(serve_OCPPv16(ip_addr, port))
    loop.create_task(simflow_diagnostics(server_url, id_tag, name))

async def serve(lport):
    logger.info("EVSETOOL::Serving OCPP1.6 on port %d" % lport)
    await serve_OCPPv16('0.0.0.0', lport)

def sniff(log_sniffed=False):
    logger.info("Starting sniffer...")
    
    ifaces = scapy.interfaces.get_if_list()
    logger.debug(f"Found ifaces: {ifaces}")
    procs = []
    for iface in ifaces:
        try:
            proc = multiprocessing.Process(target=sniffer_main, args=(iface,log_sniffed,))
            proc.start()
            logger.info(f"Now sniffing traffic on iface '{iface}'")
            procs.append(proc)
        except KeyboardInterrupt:
            logger.info("exiting here")

    proc_states = {proc: proc.is_alive() for proc in procs}
    while True:
        for proc in procs: 
            cur_state = proc.is_alive()
            if proc.is_alive() != proc_states[proc]:
                logger.info(f"Sniffer process '{proc}' has changed state: is_alive={cur_state}")
                proc_states[proc] = cur_state
        time.sleep(3)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, exiting.")
