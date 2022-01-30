# PCAP_RPARSER

CLI program writen in Rust to parse pcap file network capture of CableLabs R-PHY protocol.

## Installation

```bash
# Download repo
cargo run --release
```

## TODOs

- ansi term (color)
- Add filtering support. e.i. add option to filter by message type, packet, etc..
- Analysis and Statistics. Timing between messages, keep alives, response delays etc..
- Change the TLV parsing from hard coded to a HashMap or dB of settings with each definition and decoding instructions.
- Real time capturing.

## Usage

- Capture the communication via tcpdump: `tcpdump -i <if> -s0 tcp port 8190 -w filename.pcap`
- `./pcap_parser filename.pcap`
