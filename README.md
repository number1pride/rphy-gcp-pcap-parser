# PCAP_RPARSER

CLI program writen in Rust to parse Cable Labs R-PHY protocol. It is hard set to only decode GCP control protocol.

## Installation

```bash

```

## TODOs

- ansi term (color)
- Add filtering support. e.i. add option to filter by message type, packet, etc..
- Add statistics analysis. Timing between messages, keep alives, response delays etc..
- Change the TLV parsing from hard coded to a HashMap or dB of settings with each definition and decoding instructions.
- Real time capturing capabilities.

## Usage

- Capture the communication via tcpdump.
- `tcpdump -i <if> -s0 tcp port 8190 -w filename.pcap`
- pcap_parser filename.pcap
