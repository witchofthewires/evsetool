# evsetool

A command-line utility to probe EVSE and CSMS over OCPP1.6, and sniff OCPP traffic over LAN.

## Description

Open Charge Point Protocol (OCPP) is used to communicate betweeen Electric Vehicle Supply Equipment (EVSE) and Charge Station Management Systems (CSMS). This tool makes use of the OCPP library provided by MobilityHouse to query these systems for purposes of red team engagement. Using scapy, evsetool can also listen for all OCPP1.6 traffic sent over the local network (i.e. the WiFi network the EVSE is connected to). 

Versions 2.0 and later of the OCPP protocol implement actual encryption, so the purpose of this tool in its current form is to demonstrate the vulnerability of OCPP1.6 in order to speed adoption of newer versions of the protocol.

*** This tool is for educational and awareness purposes only. Do NOT use this tool to attempt to breach systems for which you do not have explicit authorization to do so. The author(s) of this tool are not liable for any misuse of the tool ***

## Getting Started

### Dependencies

evsetool requires the following dependencies:
  - [Python3](https://www.python.org/downloads/)

The tutorial in this section requires the following additional dependencies:
  - [Docker](https://docs.docker.com/get-started/get-docker/), with Docker Compose available

### Installing

#### Docker
Build the image:
```
docker build -t evsetool . --no-cache
```

Run the container and enter into interactive mode:
```
docker run -it evsetool
```

#### Windows
To install:
```
git clone https://github.com/witchofthewires/evsetool.git
cd evsetool
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
pip install . --force-reinstall
```
To run associated tests:
```
python -m pytest -v
```

#### Linux
To install:
```
git clone https://github.com/witchofthewires/evsetool.git
cd evsetool
make init
make install
```
To run associated tests:
```
make test
```

### Testing with StEVe
The following instructions apply to Linux environments only.

To install [StEVe](https://github.com/steve-community/steve), an open source CSMS, for purposes of testing:
```
git clone https://github.com/steve-community/steve.git
cd steve
sudo docker-compose up -d
```

Wait about 5 minutes for Docker Compose to bring the StEVE application online, then execute the following:
```
make init-steve-db
```

To run the sniffer, execute the following in the evsetool directory:
```
sudo venv/bin/python -m evsetool --sniff -v
```

To query the CSMS with a dummy transaction, open a different terminal and execute the following in the same directory:
```
venv/bin/python -m evsetool --csms -v
```

If all goes well, your output should resemble the following.
![Screenshot showing an example use of the evsetool. There are two terminals. The right terminal interacts with the CSMS server, while the left terminal sniffs and decodes the OCPP traffic.](static/transaction_simflow.png)

## Development Roadmap
- [x] Add roadmap to README
- [x] Parse OCPP1.6 Core on wired LAN/local loopback
- [x] Decrypt 802.11 traffic for WPA-PSK key material
- [ ] Combine previous two steps to decrypt and decode OCPP1.6 Wifi traffic on the fly (TABLED)
- [x] Add interactive CLI option
- [x] Add Docker support
- [x] Support pip deployment
- [ ] Implement all OCPP1.6 messages/profiles (est. 2025-7-10)
- [ ] Add attack options (TABLED)
    - [ ] EvilCSMS generic MITM prestage
    - [ ] Unauthorized start/stop transaction
    - [ ] Malicious firmware update
- [ ] Update other projects to support OCPP1.6 protocols (est. 2025-12-31)
    - [ ] Wireshark
        - [ ] WebSockets over Wifi/sniffed 802.11
        - [ ] OCPP1.6
    - [ ] Scapy
        - [ ] WebSockets
        - [ ] Real-time 802.11 WPA-PSK decryption
        - [ ] OCPP1.6
- [ ] Implement additional 802.11 support (est 2025-12-31)
    - [ ] WEP
    - [ ] WPA3

See the [open issues](https://github.com/othneildrew/Best-README-Template/issues) for a full list of proposed features (and known issues).

## License

This project is licensed under the [MIT License](LICENSE.md) - see the [LICENSE.md](LICENSE.md) file for
details

## Acknowledgements
[Starting point for WebSocket parser](https://github.com/mutantzombie/WebSocketNotes/blob/main/scapy/WebSocket.py)

[Wifi Decryption](https://github.com/TheNiska/WPA2-PSK-Decryptor/blob/main/decryptor_multiprocess.py)