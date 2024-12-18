FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN apt update && apt install -y libpcap0.8
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "src/evsetool", "--sniff", "-v" ]
