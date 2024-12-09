import asyncio
import logging
import websockets
import sys 
import time
import datetime 

#from ocpp.v201.enums import RegistrationStatusType
#from ocpp.v201 import call
#from ocpp.v201 import ChargePoint as cp
#from ocpp.v16.enums import RegistrationStatus
from ocpp.v16 import call
from ocpp.v16 import ChargePoint as cp

CSMS_URL = "ws://127.0.0.1:8180/steve/websocket/CentralSystemService"
ID_TAG = "01234567890123456789"
MODEL = "WW1959"
VENDOR = "WitchWires"
CP_NAME = "CP_1"
CONNECTOR_ID = 1
METER_START = 1000
METER_STOP = 2000

logging.basicConfig(level=logging.INFO)

class OCPPv16ChargePoint(cp):

    def __init__(self, *args, **kwargs):
        self.transactions = []
        self.id_tag = ID_TAG if 'id_tag' not in kwargs else kwargs['id_tag']
        super().__init__(*args, **kwargs)

    async def send_boot_notification(self):
        req = call.BootNotification(charge_point_model=MODEL, charge_point_vendor=VENDOR)
        res = await self.call(req)

    async def send_heartbeat(self):
        req = call.Heartbeat()
        res = await self.call(req)

    async def beat_heart(self):
        while True: 
            time.sleep(10)
            await self.send_heartbeat()

    async def authorize(self, id_tag):
        req = call.Authorize(id_tag)
        res = await self.call(req)

    async def start_transaction(self, connector_id, id_tag, meter_start, timestamp, reservation_id=None):
        req = call.StartTransaction(connector_id, id_tag, meter_start, timestamp, reservation_id=reservation_id)
        res = await self.call(req)
        self.transactions.append(res.transaction_id)

    async def stop_transaction(self, id_tag, meter_stop, timestamp, transaction_id, reason=None, transaction_data=None):
        req = call.StopTransaction(meter_stop, timestamp, transaction_id, reason, id_tag, transaction_data)
        await self.call(req)

async def run_chargepoint(name = None):
    if name is None: name = CP_NAME
    reservation_id = None

    async with websockets.connect('%s/%s' % (CSMS_URL, name),
                                  subprotocols=['ocpp1.6']) as ws:
        cp = OCPPv16ChargePoint(name, ws)
        await asyncio.gather(cp.start(), cp.send_boot_notification(), cp.authorize(cp.id_tag),
                             cp.start_transaction(CONNECTOR_ID, cp.id_tag, METER_START, timestamp=rightnow(), reservation_id=reservation_id),
                             cp.stop_transaction(cp.id_tag, METER_STOP, transaction_id=1, timestamp=rightnow(), reason=None, transaction_data=None))

def rightnow():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

if __name__ == '__main__':
    asyncio.run(run_chargepoint())