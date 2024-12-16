import asyncio
import logging
import websockets
from datetime import datetime

from ocpp.routing import on
from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call_result, datatypes, enums

from .utils import *

#from ocpp.v201 import ChargePoint as cp
#from ocpp.v201 import call_result
#from ocpp.v201.enums import RegistrationStatusType

class OCPPv16Handler(cp):
    @on('BootNotification')
    async def on_boot_notification(self, **kwargs):
        log("Received BootNotification for %s %s: %s" % (kwargs['charge_point_vendor'], kwargs['charge_point_model'], self.id))
        return call_result.BootNotification(rightnow(), 10, enums.RegistrationStatus.accepted)

async def on_connect(websocket):
    
    """ For every new charge point that connects, create a ChargePoint
    instance and start listening for messages.
    """
    if websocket.subprotocol:
        logging.info("Protocols Matched: %s", websocket.subprotocol)
    else:
        # In the websockets lib if no subprotocols are supported by the
        # client and the server, it proceeds without a subprotocol,
        # so we have to manually close the connection.
        logging.warning('Protocols Mismatched | Expected Subprotocols: %s,'
                        ' but client supports  %s | Closing connection',
                        websocket.available_subprotocols,
                        requested_protocols)
        return await websocket.close()

    charge_point_id = websocket.request.path.strip('/')
    handler = OCPPv16Handler(charge_point_id, websocket)

    await handler.start()

async def serve_OCPPv16(ip_addr, port=None, protocol=None):
    port = 8180 if port is None else port
    protocol = 'ocpp1.6' if protocol is None else protocol
    server = await websockets.serve(
        on_connect,
        ip_addr,
        port,
        subprotocols=[protocol]
    )
    logging.info("CSMS Started, serving %s at ws://%s:%d" % (protocol, ip_addr, port))
    await server.wait_closed()
