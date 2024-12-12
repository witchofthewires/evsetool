import asyncio
import logging
import websockets
import sys 
import time
import datetime 
import argparse

#from ocpp.v201.enums import RegistrationStatusType
#from ocpp.v201 import call
#from ocpp.v201 import ChargePoint as cp
#from ocpp.v16.enums import RegistrationStatus
from ocpp.v16 import call
from ocpp.v16 import ChargePoint as cp

import sniffer

CSMS_URL = "ws://127.0.0.1:8180/steve/websocket/CentralSystemService"
ID_TAG = "01234567890123456789"
CP_NAME = "CP_1"
CONNECTOR_ID = 2
METER_START = 1000
METER_STOP = 2000

def log(msg):
    print("[*] %s - %s" % (rightnow(), msg))

def rightnow():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

class OCPPv16ChargePoint(cp):

    def __init__(self, id_tag, *args, **kwargs):
        self.transactions = []
        self.id_tag = id_tag
        self.vendor = 'TODO'
        self.model = 'CHANGEME'
        super().__init__(*args, **kwargs)

    async def boot_notification(self):
        req = call.BootNotification(charge_point_model=self.model, charge_point_vendor=self.vendor)
        res = await self.call(req)
        log("sent BootNotification for %s %s" % (self.vendor, self.model))

    async def heartbeat(self):
        req = call.Heartbeat()
        res = await self.call(req)

    async def beat_heart(self):
        while True: 
            time.sleep(10)
            await self.heartbeat()

    async def authorize(self, id_tag):
        req = call.Authorize(id_tag)
        res = await self.call(req)
        if res.id_tag_info['status'] == 'Accepted': log("Authorized with tag <%s>" % id_tag)
        else:
            # TODO raise exception
            log("Failed to authorize with id_tag <%s>" % id_tag)

    async def diagnostics_status_notification(self, msg):
        req = call.DiagnosticsStatusNotification(msg)
        res = await self.call(req)
        log("Sent DiagnosticStatusNotification <%s>" % msg)

    async def firmware_status_notification(self, msg):
        req = call.FirmwareStatusNotification(msg)
        res = await self.call(req)
        log("Sent FirmwareStatusNotification <%s>" % msg)

    async def start_transaction(self, connector_id, id_tag, meter_start, timestamp, reservation_id=None):
        req = call.StartTransaction(connector_id, id_tag, meter_start, timestamp, reservation_id=reservation_id)
        res = await self.call(req)
        self.transactions.append(res.transaction_id)
        if res.id_tag_info['status'] == 'Accepted': log("CSMS accepted StartTransaction")
        else:
            # TODO raise exception
            log("CSMS denied StartTransaction")

    async def stop_transaction(self, id_tag, meter_stop, timestamp, transaction_id, reason=None, transaction_data=None):
        if transaction_id is None: transaction_id=0 # TODO fix this
        req = call.StopTransaction(meter_stop, timestamp, transaction_id, reason, id_tag, transaction_data)
        res = await self.call(req)
        if res.id_tag_info['status'] == 'Accepted': log("CSMS accepted StopTransaction")
        else:
            # TODO raise exception
            log("CSMS denied StopTransaction")

async def simflow_diagnostics(url, id_tag, name = None):
    if name is None: name = CP_NAME
    reservation_id = None

    async with websockets.connect('%s/%s' % (url, name),
                                  subprotocols=['ocpp1.6']) as ws:
        cp = OCPPv16ChargePoint(id_tag, name, ws)
        await asyncio.gather(cp.start(),
                             cp.boot_notification(), 
                             cp.authorize(cp.id_tag),
                             cp.firmware_status_notification(msg='Installed'),
                             cp.diagnostics_status_notification(msg='Uploading'))

async def simflow_transaction(url, id_tag, name = None):
    if name is None: name = CP_NAME
    reservation_id = None

    async with websockets.connect('%s/%s' % (url, name),
                                  subprotocols=['ocpp1.6']) as ws:
        cp = OCPPv16ChargePoint(id_tag, name, ws)
        await asyncio.gather(cp.start(),
                             cp.boot_notification(), 
                             cp.authorize(cp.id_tag),
                             cp.start_transaction(CONNECTOR_ID, cp.id_tag, METER_START, timestamp=rightnow(), reservation_id=reservation_id),
                             cp.stop_transaction(cp.id_tag, METER_STOP, transaction_id=None, timestamp=rightnow(), reason=None, transaction_data=None))
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='EVSE Red Team Tool')
    parser.add_argument('-v', '--verbose', action='store_true',
                    help='Show full OCPP traffic output')
    parser.add_argument('--csms', type=str,
                    help='URL of CSMS to query')
    parser.add_argument('-i', '--id', type=str,
                    help='20-character string uniquely identifying the EVSE')
    parser.add_argument('--vendor', type=str, default='WitchWires',
                    help='Company which produced the EVSE')
    parser.add_argument('--model', type=str, default='WW1959',
                    help='Name of the specific model of EVSE')
    parser.add_argument('--name', type=str, default='CP_1',
                    help='API endpoint for the EVSE')
    
    args = parser.parse_args()
    url = CSMS_URL if args.csms is None else args.csms
    id_tag = ID_TAG if args.id is None else args.id
    log_level = logging.INFO if args.verbose else logging.ERROR
    logging.basicConfig(level=log_level)
    args = parser.parse_args()
    asyncio.run(simflow_diagnostics(url, id_tag, args.name))
