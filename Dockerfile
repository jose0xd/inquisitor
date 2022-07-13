FROM gcc:9.5.0

RUN apt update && apt -y install libpcap-dev libnet-dev

WORKDIR /usr/src/
