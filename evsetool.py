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

logging.basicConfig(level=logging.INFO)

class ChargePoint(cp):

    def __init__(self, *args, **kwargs):
        self.transactions = []
        super().__init__(*args, **kwargs)

    async def send_boot_notification(self):
        request = call.BootNotification(charge_point_model="WW1959", charge_point_vendor="WitchWires")
        response = await self.call(request)

    async def send_heartbeat(self):
        request = call.Heartbeat()
        response = await self.call(request)

    async def beat_heart(self):
        while True: 
            time.sleep(10)
            await self.send_heartbeat()

    async def authorize(self, id_tag):
        request = call.Authorize(id_tag)
        response = await self.call(request)

    async def start_transaction(self, connector_id, id_tag, meter_start, timestamp, reservation_id=None):
        request = call.StartTransaction(connector_id, id_tag, meter_start, timestamp, reservation_id=reservation_id)
        response = await self.call(request)
        self.transactions.append(response.transaction_id)

    async def stop_transaction(self, id_tag, meter_stop, timestamp, transaction_id, reason=None, transaction_data=None):
        request = call.StopTransaction(meter_stop, timestamp, transaction_id, reason, id_tag, transaction_data)
        await self.call(request)

async def run_chargepoint(name = None, id_tag='01234567890123456789'):
    if name is None: name = 'CP_1'
    connector_id = 1
    meter_start = 1000
    meter_stop = 2000
    reservation_id = None
    timestamp = rightnow()

    async with websockets.connect('%s/%s' % (CSMS_URL, name),
                                  subprotocols=['ocpp1.6']) as ws:
        cp = ChargePoint(name, ws)
        await asyncio.gather(cp.start(), cp.send_boot_notification(), cp.authorize(id_tag),
                             cp.start_transaction(connector_id, id_tag, meter_start, timestamp, reservation_id),
                             cp.stop_transaction(id_tag, meter_stop, transaction_id=1, timestamp=rightnow(), reason=None, transaction_data=None))

def rightnow():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) >= 2 else None
    asyncio.run(run_chargepoint(name))