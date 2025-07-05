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

logger = logging_setup(__name__, logging.DEBUG)

class OCPPv16Handler(cp):

    def __init__(self, name, ws):
        self.transactions = {}
        self.transaction_count = 0
        super().__init__(name, ws)

    @on('BootNotification')
    async def boot_notification(self, **kwargs):
        logger.info("%s (%s %s) sent BootNotification" % (self.id, kwargs['charge_point_vendor'], kwargs['charge_point_model']))
        return call_result.BootNotification(rightnow(), 10, enums.RegistrationStatus.accepted)
    
    @on('Authorize')
    async def authorize(self, **kwargs):
        logger.info("%s requested Authorize for id_tag %s\t\tACCEPTED" % (self.id, kwargs['id_tag']))
        return call_result.Authorize(datatypes.IdTagInfo(enums.AuthorizationStatus.accepted, None, None))
    
    @on('DataTransfer')
    async def data_transfer(self, **kwargs):
        logger.info("%s sent DataTransfer: %s:%s\t\tACCEPTED" % (self.id, kwargs['vendor_id'], kwargs['message_id']))
        return call_result.DataTransfer(enums.DataTransferStatus.accepted)
    
    @on('DiagnosticsStatusNotification')
    async def diagnostics_status_notification(self, **kwargs):
        logger.info("%s sent DiagnosticStatusNotification: %s" % (self.id, kwargs['status']))
        return call_result.DiagnosticsStatusNotification()

    @on('FirmwareStatusNotification')
    async def firmware_status_notification(self, **kwargs):
        logger.info("%s sent FirmwareStatusNotification: %s" % (self.id, kwargs['status']))
        return call_result.FirmwareStatusNotification()
    
    @on('Heartbeat')
    async def heartbeat(self):
        return call_result.Heartbeat(rightnow())

    @on('MeterValues')
    async def meter_values(self, **kwargs):
        logger.info("%s sent MeterValues: %s:%s" % (self.id, kwargs['connector_id'], kwargs['meter_value']))
        return call_result.MeterValues()
    
    @on('StartTransaction')
    async def start_transaction(self, **kwargs):
        self.transaction_count += 1
        logger.info("%s requested StartTransaction for id_tag %s\t\tACCEPTED" % (self.id, kwargs['id_tag']))
        self.transactions[self.transaction_count] = call_result.StartTransaction(self.transaction_count, 
                                                                                 datatypes.IdTagInfo(enums.AuthorizationStatus.accepted, None, None))
        return self.transactions[self.transaction_count]
    
    @on('StatusNotification')
    async def status_notification(self, **kwargs):
        logger.info("%s sent StatusNotification { %s:%s }" % (self.id, kwargs['status'], kwargs['info']))
        self.transactions[self.transaction_count] = call_result.StatusNotification()
        return self.transactions[self.transaction_count]
    
    @on('StopTransaction')
    async def stop_transaction(self, **kwargs):
        logger.info("%s requested StopTransaction for id_tag %s\t\tACCEPTED" % (self.id, kwargs['id_tag']))
        self.transactions[self.transaction_count] = call_result.StopTransaction(datatypes.IdTagInfo(enums.AuthorizationStatus.accepted, None, None))
        return self.transactions[self.transaction_count]
    
async def on_connect(websocket):
    
    """ For every new charge point that connects, create a ChargePoint
    instance and start listening for messages.
    """
    
    try:
        requested_protocols = websocket.request.headers['Sec-WebSocket-Protocol']
    except KeyError:
        logger.info("Client hasn't requested any Subprotocol. "
                     "Closing Connection")
        return await websocket.close()
    
    logger.info('got to this point')
    if websocket.subprotocol:
        logger.info("Protocols Matched: %s", websocket.subprotocol)
    else:
        # In the websockets lib if no subprotocols are supported by the
        # client and the server, it proceeds without a subprotocol,
        # so we have to manually close the connection.
        logger.warning('Protocols Mismatched | Expected Subprotocols: %s,'
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
    logger.info("CSMS Started, serving %s at ws://%s:%d" % (protocol, ip_addr, port))
    await server.wait_closed()
