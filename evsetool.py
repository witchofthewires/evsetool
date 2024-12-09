import asyncio
import logging
import websockets
import sys 
import time

from ocpp.v201.enums import RegistrationStatusType
from ocpp.v201 import call
from ocpp.v201 import ChargePoint as cp

CSMS_URL = "ws://127.0.0.1:8180/steve/websocket/CentralSystemService"

logging.basicConfig(level=logging.INFO)

class ChargePoint(cp):

    async def send_boot_notification(self):
        request = call.BootNotification(
            charging_station={
                'model': 'WW1959',
                'vendor_name': 'WitchWires'
            },
            reason='PowerUp'
        )
        response = await self.call(request)

    async def send_heartbeat(self):
        request = call.Heartbeat()
        response = await self.call(request)

    async def beat_heart(self):
        while True: 
            time.sleep(1)
            await self.send_heartbeat()

async def run_chargepoint(name = None):
    if name is None: name = 'CP_1'
    async with websockets.connect('%s/%s' % (CSMS_URL, name),
                                  subprotocols=['ocpp1.6']) as ws:
        cp = ChargePoint(name, ws)
        await asyncio.gather(cp.start(), cp.send_boot_notification(), cp.beat_heart())

if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) >= 2 else None
    asyncio.run(run_chargepoint(name))