use clap::{App, Arg};

mod parsers;
use crate::parsers::gcp_parser::parser;

fn main() {
    let matches = App::new("pcap_rparser - PCAP RPHY Parser.")
        // .color(ColorChoice::Auto)
        .version("0.1")
        .author("Luis R Rosado <luisr.rosado@outlook.com")
        .about("Decodes GCP messages from PCAP network capture files.")
        .arg(
            Arg::new("PCAP_FILE")
                .help("File path.")
                .required(true)
                .index(1),
        )
        .get_matches();

    let file_name = matches.value_of("PCAP_FILE").unwrap();

    parser(file_name);
}
