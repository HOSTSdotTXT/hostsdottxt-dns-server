use deadpool_postgres::{Manager, ManagerConfig, Pool};
use futures_util::StreamExt;
use lazy_static::lazy_static;
use rand::seq::SliceRandom;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio_postgres::NoTls;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::rdata::{SOA, TXT};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::udp::UdpStream;
use trust_dns_proto::xfer::SerialMessage;
use trust_dns_proto::{BufDnsStreamHandle, DnsStreamHandle};

lazy_static! {
    // TODO: Investigate performance of checking type in SQL and needing two queries vs checking type in code
    static ref GET_DOMAIN_SQL: &'static str =
        "SELECT name,type,content,ttl FROM records WHERE name = $1";
    static ref GET_ZONE_SQL: &'static str =
        "SELECT count(id) FROM zones WHERE $1 LIKE '%' || id";
    static ref INSERT_METRICS_SQL: &'static str =
        "INSERT INTO queries (ip, qname, qtype, rcode, duration_us, host) VALUES ($1, $2, $3, $4, $5, $6)";
}

#[derive(Clone)]
pub struct FdnsRecord {
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub ttl: i32,
}
struct Metrics {
    source_ip: IpAddr,
    qname: String,
    qtype: String,
    rcode: String,
    duration_us: i64,
}

#[tokio::main]
async fn main() {
    if env::args().nth(1) == Some("--version".to_string()) {
        println!(
            "{}",
            option_env!("CARGO_PKG_VERSION").unwrap_or_else(|| "unknown")
        );
        return;
    }

    dotenvy::dotenv().ok();
    env_logger::init();
    log::info!(
        "Starting {} v{}",
        option_env!("CARGO_PKG_NAME").unwrap_or_else(|| "dns-server"),
        option_env!("CARGO_PKG_VERSION").unwrap_or_else(|| "unknown")
    );

    let pg_config =
        tokio_postgres::Config::from_str(&env::var("DATABASE_URL").expect("DATABASE_URL not set"))
            .unwrap();
    let mgr_config = ManagerConfig {
        recycling_method: deadpool_postgres::RecyclingMethod::Fast,
    };
    let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
    let pg_pool = Arc::new(Pool::builder(mgr).max_size(64).build().unwrap());
    log::info!("Connected to data postgres");

    let metrics_pool = Arc::new(
        PgPoolOptions::new()
            .max_connections(12)
            .connect(&env::var("METRICS_URL").expect("METRICS_URL not set"))
            .await
            .unwrap(),
    );
    log::info!("Connected to metrics postgres");

    let addr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| String::from("[::]:53"))
        .parse::<SocketAddr>()
        .expect("Unable to parse bind address");
    log::info!("Binding to udp://{}", addr);

    let socket = UdpSocket::bind(&addr)
        .await
        .unwrap_or_else(|_| panic!("Unable to bind to {addr}"));
    let (mut reciever, sender) =
        UdpStream::with_bound(socket, "127.0.0.254:9875".parse::<SocketAddr>().unwrap());
    let sender = Arc::new(Mutex::new(sender));
    log::info!("Succesfully bound and listenining to udp://{}", addr);

    loop {
        let packet = reciever.next().await;
        let packet = match packet {
            Some(packet) => packet,
            _ => continue,
        };
        log::trace!("Recieved packet");

        match packet {
            Ok(raw_message) => {
                let sender = Arc::clone(&sender);
                let pg_pool = Arc::clone(&pg_pool);
                let metrics_pool = Arc::clone(&metrics_pool);
                log::trace!("Spawning new task");
                tokio::spawn(async move {
                    let metrics = handle_message(raw_message, &pg_pool, sender).await;
                    log::trace!("Packet handled, logging metrics");
                    if let Ok(metrics) = metrics {
                        let hostname = match hostname::get() {
                            Ok(hostname) => hostname.to_str().unwrap_or("unknown").to_owned(),
                            Err(_) => String::from("unknown"),
                        };
                        if metrics.duration_us > 5 * 1000 {
                            log::warn!("Query took over 5ms: {} {}", metrics.qname, metrics.qtype)
                        }
                        if let Err(e) = sqlx::query(&INSERT_METRICS_SQL)
                            .bind(&metrics.source_ip)
                            .bind(&metrics.qname)
                            .bind(&metrics.qtype)
                            .bind(&metrics.rcode)
                            .bind(metrics.duration_us)
                            .bind(hostname)
                            .execute(&*metrics_pool)
                            .await
                        {
                            log::error!("{e}");
                        }
                    }
                });
                log::trace!("Task completed")
            }
            Err(e) => {
                log::error!("{e}");
                continue;
            }
        }
    }
}

async fn handle_message(
    raw_message: SerialMessage,
    postgres: &Arc<Pool>,
    sender: Arc<Mutex<BufDnsStreamHandle>>,
) -> Result<Metrics, ()> {
    let src = raw_message.addr();
    let start = Instant::now();
    let postgres_t = postgres.get();
    log::debug!("Recieved packet from {src}");

    let mut message = match Message::from_vec(raw_message.bytes()) {
        Ok(message) => message,
        Err(e) => {
            log::error!("{e}");
            return Err(());
        }
    };
    log::trace!("[{}] Parsed message", message.id());

    message.set_response_code(ResponseCode::NoError);

    let query = message.queries().get(0).unwrap().to_owned();

    let qname = query.name().to_string().to_lowercase();
    let qtype = query.query_type().to_string();
    log::trace!("[{}] Querying for {qname}", message.id());

    let postgres = postgres_t.await.unwrap();
    let statement = postgres.prepare_cached(&GET_DOMAIN_SQL).await.unwrap();
    let rows = postgres.query(&statement, &[&qname]).await.unwrap();
    let records: Vec<FdnsRecord> = rows
        .iter()
        .map(|r| FdnsRecord {
            name: r.get(0),
            record_type: r.get(1),
            content: r.get(2),
            ttl: r.get(3),
        })
        .collect();
    log::trace!("[{}] Query for {qname} completed", message.id());

    // TODO: CNAME resolution
    message.add_answers(randomize_records(
        records
            .iter()
            .filter(|r| r.record_type == qtype)
            .map(|r| {
                Record::new()
                    .set_ttl(r.ttl.try_into().unwrap())
                    .set_dns_class(DNSClass::IN)
                    .set_rr_type(RecordType::from_str(&r.record_type).unwrap())
                    .set_name(Name::from_str(&r.name).unwrap())
                    .set_data(match RecordType::from_str(&r.record_type).unwrap() {
                        RecordType::A => match r.content.parse::<Ipv4Addr>() {
                            Ok(addr) => Some(RData::A(addr)),
                            Err(e) => {
                                log::error!("Error parsing A record: {}", e);
                                None
                            }
                        },
                        RecordType::AAAA => match r.content.parse::<Ipv6Addr>() {
                            Ok(addr) => Some(RData::AAAA(addr)),
                            Err(e) => {
                                log::error!("Error parsing AAAA record: {}", e);
                                None
                            }
                        },
                        // TODO: Resolve these
                        RecordType::CNAME => match r.content.parse::<Name>() {
                            Ok(name) => Some(RData::CNAME(name)),
                            Err(e) => {
                                log::error!("Error parsing CNAME record: {}", e);
                                None
                            }
                        },
                        RecordType::NS => match r.content.parse::<Name>() {
                            Ok(name) => Some(RData::NS(name)),
                            Err(e) => {
                                log::error!("Error parsing NS record: {}", e);
                                None
                            }
                        },
                        RecordType::TXT => Some(RData::TXT(TXT::new(vec![r.content.clone()]))),
                        RecordType::SOA => match parse_soa(&r.content) {
                            Ok(soa) => Some(RData::SOA(soa)),
                            Err(_) => {
                                log::error!("Error parsing SOA record");
                                None
                            }
                        },
                        unknown => {
                            log::warn!("Unknown record type {}", unknown.to_string());
                            None
                        }
                    })
                    .clone()
            })
            .filter(|r| r.data().is_some())
            .collect(),
    ));
    log::trace!("[{}] Answers set", message.id());

    if message.answers().is_empty() {
        log::debug!(
            "[{}] No answers, querying to see if we're authoritative",
            message.id()
        );
        let statement = postgres.prepare_cached(&GET_ZONE_SQL).await.unwrap();
        let count_row = postgres.query_one(&statement, &[&qname]).await.unwrap();
        let zone_count: i64 = count_row.get(0);
        log::trace!("[{}] Query returned {} zones", message.id(), zone_count);
        if zone_count == 0 {
            message.set_response_code(ResponseCode::Refused);
        } else if records.is_empty() {
            message.set_response_code(ResponseCode::NXDomain);
            // TODO: Set additional SOA
        }
    }

    message.set_message_type(MessageType::Response);
    message.set_authoritative(true);
    message.set_recursion_available(false);

    let response = SerialMessage::new(message.to_vec().unwrap(), src);
    log::trace!("[{}] Locking output stream", message.id());
    let sender = (*sender).lock().unwrap();
    let mut sender = sender.with_remote_addr(src);
    match sender.send(response) {
        Ok(_) => {
            log::debug!("[{}] success", message.id());
        }
        Err(e) => {
            log::error!("[{}] {e}", message.id());
        }
    };
    log::trace!("[{}] Response sent", message.id());

    Ok(Metrics {
        source_ip: src.ip(),
        qname: query.name().to_string(),
        qtype,
        rcode: match message.response_code() {
            ResponseCode::NoError => String::from("NOERROR"),
            ResponseCode::NXDomain => String::from("NXDOMAIN"),
            ResponseCode::Refused => String::from("REFUSED"),
            _ => String::from("UNKNOWN"),
        },
        duration_us: start.elapsed().as_micros().try_into().unwrap(),
    })
}

fn parse_soa(content: &str) -> Result<SOA, ()> {
    let parts: Vec<String> = content
        .split_whitespace()
        .into_iter()
        .map(|s| s.to_owned())
        .collect();
    Ok(SOA::new(
        get(&parts, 0)?,
        get(&parts, 1)?,
        get(&parts, 2)?,
        get(&parts, 3)?,
        get(&parts, 4)?,
        get(&parts, 5)?,
        get(&parts, 6)?,
    ))
}

fn get<T: FromStr>(parts: &[String], index: usize) -> Result<T, ()> {
    match parts.get(index) {
        Some(part) => match part.parse::<T>() {
            Ok(name) => Ok(name),
            Err(_) => Err(()),
        },
        None => Err(()),
    }
}

fn randomize_records(original_records: Vec<Record>) -> Vec<Record> {
    let mut a_records: Vec<Record> = vec![];
    let mut aaaa_records: Vec<Record> = vec![];
    let mut ns_records: Vec<Record> = vec![];
    let mut other_records: Vec<Record> = vec![];
    for record in original_records {
        match record.rr_type() {
            RecordType::A => a_records.push(record),
            RecordType::AAAA => aaaa_records.push(record),
            RecordType::NS => ns_records.push(record),
            _ => other_records.push(record),
        }
    }
    let mut rng = rand::thread_rng();
    a_records.shuffle(&mut rng);
    aaaa_records.shuffle(&mut rng);
    ns_records.shuffle(&mut rng);

    [a_records, aaaa_records, ns_records, other_records].concat()
}
