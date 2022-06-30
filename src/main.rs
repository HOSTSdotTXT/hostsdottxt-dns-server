#![deny(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};

use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{DNSClass, RData, Record, RecordType};
use trust_dns_proto::udp::UdpStream;
use trust_dns_proto::xfer::SerialMessage;
use trust_dns_proto::{BufDnsStreamHandle, DnsStreamHandle};

#[tokio::main]
async fn main() {
    fast_log::fast_log::init(
        fast_log::Config::new()
            .console()
            .level(log::LevelFilter::Off),
    )
    .unwrap();

    let addr = String::from("127.0.0.1:53")
        .parse::<SocketAddr>()
        .expect("Unable to parse bind address");

    let socket = UdpSocket::bind(&addr)
        .await
        .unwrap_or_else(|_| panic!("Unable to bind to {addr}"));
    let (mut reciever, sender) =
        UdpStream::with_bound(socket, "127.0.0.254:9875".parse::<SocketAddr>().unwrap());
    let sender = Arc::new(Mutex::new(sender));

    loop {
        let packet = reciever.next().await;
        let packet = match packet {
            Some(packet) => packet,
            _ => continue,
        };

        match packet {
            Ok(raw_message) => {
                let sender = Arc::clone(&sender);
                tokio::spawn(async move {
                    handle_message(raw_message, sender).await;
                });
            }
            Err(e) => {
                log::error!("{e}");
                continue;
            }
        }
    }
}

async fn handle_message(raw_message: SerialMessage, sender: Arc<Mutex<BufDnsStreamHandle>>) {
    let src = raw_message.addr();
    log::debug!("Recieved packet from {src}");

    let mut message = match Message::from_vec(raw_message.bytes()) {
        Ok(message) => message,
        Err(e) => {
            log::error!("{e}");
            return;
        }
    };

    for query in message.clone().queries() {
        if query.name().to_string() == "example.com." {
            message.add_answer(
                Record::new()
                    .set_ttl(60)
                    .set_dns_class(DNSClass::IN)
                    .set_rr_type(RecordType::A)
                    .set_name(query.name().clone())
                    .set_data(Some(RData::A(Ipv4Addr::new(127, 0, 0, 1))))
                    .clone(),
            );
        }
    }

    message.set_message_type(MessageType::Response);
    message.set_authoritative(true);
    message.set_recursion_available(false);

    let response = SerialMessage::new(message.to_vec().unwrap(), src);
    let sender = (*sender).lock().unwrap();
    let mut sender = sender.with_remote_addr(src);
    match sender.send(response) {
        Ok(_) => {
            log::debug!("{} success", message.id());
        }
        Err(e) => {
            log::error!("{e}");
        }
    };
}
