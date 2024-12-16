import asyncio
import logging
import websockets
from datetime import datetime

from ocpp.routing import on
from ocpp.v201 import ChargePoint as cp
from ocpp.v201 import call_result
from ocpp.v201.enums import RegistrationStatusType

logging.basicConfig(level=logging.INFO)


class OCPPv16Handler(cp):
    @on('BootNotification')
    async def on_boot_notification(self, charging_station, reason, **kwargs):
        return call_result.BootNotificationPayload(
            current_time=datetime.utcnow().isoformat(),
            interval=10,
            status=RegistrationStatusType.accepted
        )

async def on_connect(websocket, path):
    """ For every new charge point that connects, create a ChargePoint
    instance and start listening for messages.
    """
    try:
        requested_protocols = websocket.request_headers[
            'Sec-WebSocket-Protocol']
    except KeyError:
        logging.info("Client hasn't requested any Subprotocol. "
                 "Closing Connection")
        return await websocket.close()

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

    charge_point_id = path.strip('/')
    handler = OCPPv16Handler(charge_point_id, websocket)

    await handler.start()

async def main():
    ip_addr = '0.0.0.0'
    port = 9000
    protocol = 'ocpp1.6'
    server = await websockets.serve(
        on_connect,
        ip_addr,
        port,
        subprotocols=[protocol]
    )
    logging.info("CSMS Started, serving %s at ws://%s:%d" % (protocol, ip_addr, port))
    await server.wait_closed()

if __name__ == '__main__':
    asyncio.run(main())
