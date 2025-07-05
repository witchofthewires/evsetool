FROM python:3

WORKDIR /usr/src/app

COPY . .

RUN apt update && apt install -y libpcap0.8
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install .

CMD [ "python", "-m", "evsetool", "-i" ]
