import asyncio
import logging
import websockets
import sys 
import time
import datetime 
import argparse

from scapy.utils import rdpcap

#from ocpp.v201.enums import RegistrationStatusType
#from ocpp.v201 import call
#from ocpp.v201 import ChargePoint as cp
#from ocpp.v16.enums import RegistrationStatus
from ocpp.v16 import call, datatypes, enums
from ocpp.v16 import ChargePoint as cp

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

    async def heartbeat(self):
        req = call.Heartbeat()
        res = await self.call(req)

    async def beat_heart(self):
        while True: 
            time.sleep(10)
            await self.heartbeat()

    async def data_transfer(self, vendor_id, message_id, data=None):
        req = call.DataTransfer(vendor_id, message_id, data)
        res = await self.call(req)
        log("Sent DataTransfer message successfully")

    async def meter_values(self, connector_id, meter_values, transaction_id=None):
        req = call.MeterValues(connector_id, meter_values, transaction_id)
        res = await self.call(req)
        log("Sent MeterValues successfully")

    async def start_transaction(self, connector_id, id_tag, meter_start, timestamp, reservation_id=None):
        req = call.StartTransaction(connector_id, id_tag, meter_start, timestamp, reservation_id=reservation_id)
        res = await self.call(req)
        self.transactions.append(res.transaction_id)
        if res.id_tag_info['status'] == 'Accepted': log("CSMS accepted StartTransaction")
        else:
            # TODO raise exception
            log("CSMS denied StartTransaction")

    async def status_notification(self, 
                                  connector_id, 
                                  error_code, 
                                  status, 
                                  info=None, 
                                  timestamp=None, 
                                  vendor_id=None, 
                                  vendor_error_code=None):
        req = call.StatusNotification(connector_id, 
                                      error_code,
                                      status, 
                                      timestamp, 
                                      info, 
                                      vendor_id, 
                                      vendor_error_code)
        req = await self.call(req)
        log("StatusNotification successful")

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
        meter_values = [datatypes.MeterValue(rightnow(), [datatypes.SampledValue('100', 
                                                                                enums.ReadingContext.other, 
                                                                                enums.ValueFormat.raw,
                                                                                enums.Measurand.temperature,
                                                                                'L1',
                                                                                enums.Location.body,
                                                                                enums.UnitOfMeasure.fahrenheit),
                                                         datatypes.SampledValue('99', 
                                                                                enums.ReadingContext.other, 
                                                                                enums.ValueFormat.raw,
                                                                                enums.Measurand.temperature,
                                                                                'L1',
                                                                                enums.Location.body,
                                                                                enums.UnitOfMeasure.fahrenheit),
                                                         datatypes.SampledValue('101', 
                                                                                enums.ReadingContext.other, 
                                                                                enums.ValueFormat.raw,
                                                                                enums.Measurand.temperature,
                                                                                'L1',
                                                                                enums.Location.body,
                                                                                enums.UnitOfMeasure.fahrenheit)])]       
        vendor_id = 'A' *255
        message_id = 'B' *50
        data = "there are spirits watching over me/they refuse my filthy hands"                
        await asyncio.gather(cp.start(),
                             cp.boot_notification(), 
                             cp.authorize(cp.id_tag),
                             cp.firmware_status_notification(msg='Installed'),
                             cp.diagnostics_status_notification(msg='Uploading'),
                             cp.meter_values(1, meter_values),
                             cp.data_transfer(vendor_id, message_id, data))

async def simflow_transaction(url, id_tag, name=None):
    if name is None: name = CP_NAME
    reservation_id = None

    async with websockets.connect('%s/%s' % (url, name),
                                  subprotocols=['ocpp1.6']) as ws:
        cp = OCPPv16ChargePoint(id_tag, name, ws)
        connector_id = 1
        meter_start = 1000
        meter_stop = 2000
        vendor_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        vendor_error_code = "200"
        await asyncio.gather(cp.start(),
                             cp.boot_notification(), 
                             cp.authorize(cp.id_tag),
                             cp.start_transaction(connector_id, 
                                                  cp.id_tag, 
                                                  meter_start, 
                                                  timestamp=rightnow(), 
                                                  reservation_id=reservation_id),
                             cp.status_notification(connector_id, 
                                                    enums.ChargePointErrorCode.no_error, 
                                                    enums.ChargePointStatus.charging, 
                                                    "all good here, how are you?", 
                                                    rightnow(), 
                                                    vendor_id, 
                                                    vendor_error_code),
                             cp.stop_transaction(cp.id_tag, 
                                                 meter_stop, 
                                                 transaction_id=None, 
                                                 timestamp=rightnow(), 
                                                 reason=None, 
                                                 transaction_data=None))














































