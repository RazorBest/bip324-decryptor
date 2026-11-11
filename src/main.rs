mod iptables;
mod logging;
mod merger;
mod pcap_writer;
mod util;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bip324_mitm::MitmBIP324;
use clap::Parser;
use etherparse::{IpNumber, Ipv4HeaderSlice};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use rtrb::{Consumer, Producer, RingBuffer};
use secp256k1::rand;
use slapp::nfq::{SlappNfqIpv4Tcp, SlappNfqNetOptions};
use slapp::tcp::SlappTcpError;
use slapp::{
    ApplicationDataSlappHandler, InterceptVerdict, NetworkSlappSpy, SlappIpv4, SlappTcp,
    TransportSlappSpy,
};
use tracing::{self, debug, warn};

use crate::merger::{MergerLogger, PlaintextRecord};
use crate::pcap_writer::{
    Dumper, DumperOptions, MonotonicCounter, PacketRecord, PcapWriter, enhanced_packet_from_payload,
};
use crate::util::producer_blocking_push;

// This depends on the desired bandwitdh, and how frequent the consumer checks the queue
const PLAINTEXT_QUEUE_SIZE: usize = 8192;
const PACKET_QUEUE_SIZE: usize = 8192;

fn interface_ipv4_ips(interface: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();

    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return ips;
        }

        let mut current = ifap;

        while !current.is_null() {
            let entry = &*current;

            if !entry.ifa_addr.is_null() {
                let name = CStr::from_ptr(entry.ifa_name).to_string_lossy();

                if name == interface && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET {
                    let addr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    ips.push(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
                }
            }

            current = entry.ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    ips
}

fn get_current_time_utc_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct BIP324State {
    is_bip324: bool,
    bip324: Option<MitmBIP324>,
}

impl Default for BIP324State {
    fn default() -> Self {
        Self {
            is_bip324: true,
            bip324: None,
        }
    }
}

impl BIP324State {
    fn on_data(&mut self, is_client: bool, data: &mut [u8]) -> Vec<u8> {
        if !self.is_bip324 {
            return vec![];
        }

        let bip324 = self.bip324.get_or_insert_with(|| {
            let mut rng = rand::thread_rng();
            let mut bip324 = MitmBIP324::new(&mut rng);
            bip324.ensure_garbage_includes_terminator(true).unwrap();
            bip324.enable_bytes_relay();

            bip324
        });

        let mut decrypted = vec![];

        if is_client {
            bip324.client_write(data).unwrap();
            let read = bip324.server_read(data).unwrap();
            assert_eq!(read, data.len());

            let bytes = bip324.next_bytes_client().unwrap();
            decrypted.extend_from_slice(&bytes);
        } else {
            bip324.server_write(data).unwrap();
            let read = bip324.client_read(data).unwrap();
            assert_eq!(read, data.len());

            let bytes = bip324.next_bytes_server().unwrap();
            decrypted.extend_from_slice(&bytes);
        };

        decrypted
    }
}

struct AppHandler {
    map: HashMap<u64, BIP324State>,
    plaintext_queue: Producer<PlaintextRecord>,
    suspicious: Rc<RefCell<HashSet<u64>>>,
}

impl AppHandler {
    fn new(plaintext_queue: Producer<PlaintextRecord>) -> Self {
        Self {
            map: HashMap::new(),
            plaintext_queue,
            suspicious: Rc::new(RefCell::new(HashSet::new())),
        }
    }
}

impl ApplicationDataSlappHandler for AppHandler {
    #[tracing::instrument(skip(self, counter, data))]
    fn on_data(
        &mut self,
        session_id: u64,
        is_client: bool,
        counter: i64,
        data: &mut [u8],
    ) -> InterceptVerdict {
        // Skip suspiscious packets. They are logged by TransportSpy.
        if self.suspicious.borrow_mut().get(&session_id).is_some() {
            return InterceptVerdict::Accept;
        }

        debug!("on_data seq={} len={}", counter, data.len());

        let bip324 = self.map.entry(session_id).or_default();

        let decrypted = bip324.on_data(is_client, data);

        let record = PlaintextRecord {
            session_id,
            is_client,
            counter,
            data: decrypted,
            close: false,
        };
        producer_blocking_push(&mut self.plaintext_queue, record);

        InterceptVerdict::Accept
    }

    fn close(&mut self, session_id: u64, is_client: bool) {
        if self.suspicious.borrow_mut().get(&session_id).is_some() {
            return;
        }

        let record = PlaintextRecord {
            session_id,
            is_client,
            counter: 0,
            data: vec![],
            close: true,
        };
        producer_blocking_push(&mut self.plaintext_queue, record);
    }
}

struct NetworkSpy {
    sus_producer: Rc<RefCell<Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>>>,
    before_counter: u64,
}

impl NetworkSlappSpy for NetworkSpy {
    fn before(&mut self, net_header: &[u8], data: &[u8]) {
        self.before_counter += 1;

        let Ok(ip) = Ipv4HeaderSlice::from_slice(net_header) else {
            warn!(
                "Couldn't parse net_header: {:?}",
                &net_header[..net_header.len().min(20)]
            );
            return;
        };

        if ip.protocol() == IpNumber::TCP {
            return;
        }

        let payload: Vec<u8> = net_header.iter().chain(data).copied().collect();

        // All non-TCP packets are considered suspicious
        let timestamp = get_current_time_utc_millis();
        let enhanced_packet = enhanced_packet_from_payload(payload, timestamp);

        producer_blocking_push(
            &mut self.sus_producer.borrow_mut(),
            (enhanced_packet, self.before_counter),
        );
    }
    fn after(&mut self, _net_header: &[u8], _data: &[u8], _verdict: &InterceptVerdict) {}
}

impl NetworkSpy {
    fn new(
        sus_producer: Rc<RefCell<Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>>>,
    ) -> Self {
        Self {
            sus_producer,
            before_counter: 0,
        }
    }
}

struct TransportSpy {
    packet_producer: Producer<PacketRecord>,
    counter: u64,
    unprocessed_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    sus_producer: Rc<RefCell<Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>>>,
    before_counter: u64,
    suspicious: Rc<RefCell<HashSet<u64>>>,
    host_ip: Option<[u8; 4]>,
}

impl TransportSlappSpy for TransportSpy {
    fn before(&mut self, net_header: &[u8], transport_header: &[u8], data: &[u8], session_id: u64) {
        self.before_counter += 1;

        let header: Vec<u8> = net_header.iter().chain(transport_header).copied().collect();

        use etherparse::LaxPacketHeaders;
        let parsed = LaxPacketHeaders::from_ip(&header).unwrap();

        if let Some(etherparse::TransportHeader::Udp(ref udp)) = parsed.transport {
            debug!("UDP packet");
            debug!("Packet: {:?}", udp);
        }

        let Some(etherparse::TransportHeader::Tcp(tcp)) = parsed.transport else {
            panic!("Not tcp");
        };

        let etherparse::NetHeaders::Ipv4(ip, _) = parsed.net.unwrap() else {
            panic!("Not ipv4");
        };

        use std::net::Ipv4Addr;
        debug!(
            "TCP packet before session_id={}; src: {}:{}; seq: {}, ack: {}, len: {}, syn: {}, fin: {}",
            session_id,
            Ipv4Addr::from(ip.source),
            tcp.source_port,
            tcp.sequence_number,
            tcp.acknowledgment_number,
            data.len(),
            tcp.syn,
            tcp.fin,
        );
        if let Some(host_ip) = self.host_ip {
            // If first SYN not from us
            if (tcp.syn || tcp.rst)
                && !tcp.ack
                && ip.source != host_ip
                && tcp.destination_port != 8333
            {
                debug!("Suspicious");
                self.suspicious.borrow_mut().insert(session_id);
            }
            if ip.source != host_ip && ip.destination != host_ip {
                debug!("Suspicious");
                self.suspicious.borrow_mut().insert(session_id);
            }
            if tcp.syn && !tcp.ack && ip.source == host_ip && tcp.destination_port == 80 {
                debug!("Suspicious");
                self.suspicious.borrow_mut().insert(session_id);
            }
        }

        // Push to unprocessed or suspicious
        let payload: Vec<u8> = net_header
            .iter()
            .chain(transport_header)
            .chain(data)
            .copied()
            .collect();
        let timestamp = get_current_time_utc_millis();
        let enhanced_packet = enhanced_packet_from_payload(payload, timestamp);

        if self.suspicious.borrow_mut().get(&session_id).is_some() {
            producer_blocking_push(
                &mut self.sus_producer.borrow_mut(),
                (enhanced_packet, self.before_counter),
            );
        } else {
            producer_blocking_push(
                &mut self.unprocessed_producer,
                (enhanced_packet, self.before_counter),
            );
        }
    }

    #[tracing::instrument(skip(self, net_header, transport_header, data, _verdict))]
    fn after(
        &mut self,
        net_header: &[u8],
        transport_header: &[u8],
        is_client: bool,
        data: &[u8],
        session_id: u64,
        _verdict: &InterceptVerdict,
    ) {
        if self.suspicious.borrow_mut().get(&session_id).is_some() {
            return;
        }

        self.counter += 1;

        let header: Vec<u8> = net_header.iter().chain(transport_header).copied().collect();

        let record = PacketRecord {
            monocounter: self.counter,
            timestamp: get_current_time_utc_millis(),
            session_id,
            is_client,
            header,
            data: data.to_vec(),
            close: false,
        };

        producer_blocking_push(&mut self.packet_producer, record);
    }

    #[tracing::instrument(skip(self))]
    fn close(&mut self, is_client: bool, session_id: u64) {
        debug!("Close");

        if self.suspicious.borrow_mut().get(&session_id).is_some() {
            return;
        }

        self.counter += 1;

        let record = PacketRecord {
            monocounter: self.counter,
            timestamp: get_current_time_utc_millis(),
            session_id,
            is_client,
            header: vec![],
            data: vec![],
            close: true,
        };

        producer_blocking_push(&mut self.packet_producer, record);
    }

    fn error(
        &mut self,
        net_header: &[u8],
        transport_header: &[u8],
        data: &[u8],
        session_id: u64,
        err: SlappTcpError,
    ) -> InterceptVerdict {
        debug!("Error for {}: {:?}", session_id, err);

        // the before callback was called before the session was thought to be suspicious
        if self.suspicious.borrow_mut().get(&session_id).is_none() {
            let payload: Vec<u8> = net_header
                .iter()
                .chain(transport_header)
                .chain(data)
                .copied()
                .collect();
            let timestamp = get_current_time_utc_millis();
            let enhanced_packet = enhanced_packet_from_payload(payload, timestamp);

            producer_blocking_push(
                &mut self.sus_producer.borrow_mut(),
                (enhanced_packet, self.before_counter),
            );
        }

        self.suspicious.borrow_mut().insert(session_id);

        InterceptVerdict::Accept
    }
}

impl TransportSpy {
    fn new(
        packet_producer: Producer<PacketRecord>,
        unprocessed_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
        sus_producer: Rc<RefCell<Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>>>,
        host_ip: Option<[u8; 4]>,
    ) -> Self {
        Self {
            packet_producer,
            counter: 0,
            unprocessed_producer,
            sus_producer,
            before_counter: 0,
            suspicious: Rc::new(RefCell::new(HashSet::new())),
            host_ip,
        }
    }
}

type Interceptor = SlappNfqIpv4Tcp<AppHandler, NetworkSpy, TransportSpy>;

pub async fn async_run_interceptor(
    opts: &SlappNfqNetOptions,
    running: Arc<AtomicBool>,
    plaintext_producer: Producer<PlaintextRecord>,
    packet_producer: Producer<PacketRecord>,
    unprocessed_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    sus_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    host_ip: Option<[u8; 4]>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let app_handler = AppHandler::new(plaintext_producer);

    let sus_producer_ref = Rc::new(RefCell::new(sus_producer));
    let mut transport_spy = TransportSpy::new(
        packet_producer,
        unprocessed_producer,
        Rc::clone(&sus_producer_ref),
        host_ip,
    );
    transport_spy.suspicious = Rc::clone(&app_handler.suspicious);

    let network_spy = NetworkSpy::new(sus_producer_ref);

    let transport_handler = SlappTcp::new_from(app_handler, transport_spy);
    let net_handler = SlappIpv4::new(transport_handler, network_spy);

    let mut interceptor: Interceptor = opts.open_from_handler(net_handler).unwrap();

    interceptor.intercept(running).await
}

pub fn run_merger(
    running: Arc<AtomicBool>,
    plaintext_consumer: Consumer<PlaintextRecord>,
    packet_consumer: Consumer<PacketRecord>,
    encrypted_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    plaintext_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
) {
    let mut merger = MergerLogger {
        running,
        plaintext_consumer,
        packet_consumer,
        session_map: HashMap::new(),
        close_tracker: HashMap::new(),
        encrypted_producer,
        plaintext_producer,
    };

    merger.run();
}

pub fn run_pcap_writer(
    running: Arc<AtomicBool>,
    pcap_dumper: Dumper,
    packet_consumer: Consumer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
) {
    let mut pcap_writer = PcapWriter::new(running, pcap_dumper, packet_consumer);

    pcap_writer.run();
}

pub fn run_program(
    interceptor_opts: SlappNfqNetOptions,
    dumper_opts: DumperOptions,
    running: Arc<AtomicBool>,
    host_ip: Option<[u8; 4]>,
) -> Result<(), Box<dyn Error>> {
    debug!("Interceptor started");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (plaintext_producer, plaintext_consumer) = RingBuffer::new(PLAINTEXT_QUEUE_SIZE);
    let (packet_producer, packet_consumer) = RingBuffer::new(PACKET_QUEUE_SIZE);
    let (writer_unprocessed_producer, writer_unprocessed_consumer) =
        RingBuffer::new(PACKET_QUEUE_SIZE);
    let (writer_sus_producer, writer_sus_consumer) = RingBuffer::new(PACKET_QUEUE_SIZE);
    let (writer_encrypted_producer, writer_encrypted_consumer) = RingBuffer::new(PACKET_QUEUE_SIZE);
    let (writer_plaintext_producer, writer_plaintext_consumer) = RingBuffer::new(PACKET_QUEUE_SIZE);

    let encrypted_dumper = Dumper::new(&dumper_opts);

    let mut ptxt_opts = dumper_opts.clone();
    ptxt_opts.path_prefix = format!("{}_decrypted", ptxt_opts.path_prefix);
    let plaintext_dumper = Dumper::new(&ptxt_opts);

    let mut unprocessed_opts = dumper_opts.clone();
    unprocessed_opts.path_prefix = format!("{}_unprocessed", unprocessed_opts.path_prefix);
    let unprocessed_dumper = Dumper::new(&unprocessed_opts);

    let mut sus_opts = dumper_opts.clone();
    sus_opts.path_prefix = format!("{}_suspicious", sus_opts.path_prefix);
    let sus_dumper = Dumper::new(&sus_opts);

    macro_rules! create_task {
        (clone $running:ident, $run:expr) => {{
            let $running = $running.clone();
            rt.spawn_blocking(move || $run)
        }};
    }

    let mut merger_task = create_task!(clone running, run_merger(
        running,
        plaintext_consumer,
        packet_consumer,
        writer_encrypted_producer,
        writer_plaintext_producer,
    ));

    let mut writer_unprocessed_task = create_task!(clone running, run_pcap_writer(
        running,
        unprocessed_dumper,
        writer_unprocessed_consumer,
    ));

    let mut writer_sus_task = create_task!(clone running,
        run_pcap_writer(running, sus_dumper, writer_sus_consumer)
    );

    let mut writer_plaintext_task = create_task!(clone running,
        run_pcap_writer(running, plaintext_dumper, writer_plaintext_consumer)
    );

    let mut writer_encrypted_task = create_task!(clone running,
        run_pcap_writer(running, encrypted_dumper, writer_encrypted_consumer)
    );

    let local = tokio::task::LocalSet::new();
    rt.block_on(local.run_until(async move {
        let running_clone = running.clone();
        let mut interceptor_task = tokio::task::spawn_local(async move {
            async_run_interceptor(
                &interceptor_opts,
                running_clone,
                plaintext_producer,
                packet_producer,
                writer_unprocessed_producer,
                writer_sus_producer,
                host_ip,
            )
            .await
        });

        let mut res_merger = None;
        let mut res_writer_unprocessed = None;
        let mut res_writer_sus = None;
        let mut res_writer_encrypted = None;
        let mut res_writer_plaintext = None;
        let mut res_interceptor = None;

        while res_merger.is_none()
            || res_writer_unprocessed.is_none()
            || res_writer_sus.is_none()
            || res_writer_encrypted.is_none()
            || res_writer_plaintext.is_none()
            || res_interceptor.is_none()
        {
            tokio::select! {
                res = &mut merger_task, if res_merger.is_none() => {
                    running.store(false, Ordering::SeqCst);
                    res_merger = Some(res);
                }
                res = &mut writer_unprocessed_task, if res_writer_unprocessed.is_none() => {
                    running.store(false, Ordering::SeqCst);
                    res_writer_unprocessed = Some(res);
                }
                res = &mut writer_sus_task, if res_writer_sus.is_none() => {
                    running.store(false, Ordering::SeqCst);
                    res_writer_sus = Some(res);
                }
                res = &mut writer_encrypted_task, if res_writer_encrypted.is_none() => {
                    running.store(false, Ordering::SeqCst);
                    res_writer_encrypted = Some(res);
                }
                res = &mut writer_plaintext_task, if res_writer_plaintext.is_none() => {
                    running.store(false, Ordering::SeqCst);
                    res_writer_plaintext = Some(res);
                }
                res = &mut interceptor_task, if res_interceptor.is_none() => {
                    running.store(false, Ordering::SeqCst);
                    res_interceptor = Some(res);
                }
            }
        }
    }));

    Ok(())
}

/// Adds a Ctrl+C handler that changes the "running" variable to false when the
/// signal is received. This variable can be shared by other parts of the code,
/// in order to handle exiting gracefully. The second Ctrl+C generates an exit.
fn set_ctrlc_handler(running: &Arc<AtomicBool>) {
    let state = Arc::new(AtomicUsize::new(0));
    let state_clone = state.clone();
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        let previous_state = state_clone.fetch_add(1, Ordering::SeqCst);

        if previous_state == 0 {
            println!("Initiating graceful shutdown... Press Ctrl+C again to force quit.");
        } else {
            println!("Force quit triggered. Exiting immediately.");
            std::process::exit(1); // Bypasses all Drop handlers and flushes
        }

        running_clone.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Where to store the logs. If not specified, logs are not generated.
    #[arg(long)]
    log_template: Option<PathBuf>,
    #[arg(long, default_value_t = "node".to_string())]
    node_name: String,
    /// NFQUEUE id
    #[arg(short, long, default_value_t = 0)]
    queue_num: u16,
    /// If set, change the NFQUEUE size with this value in the kernel
    #[arg(short, long)]
    max_queue_len: Option<u32>,
    /// Log level: error, warn, info, debug or trace, or a number 1-5
    #[arg(long, default_value_t = tracing::Level::INFO)]
    log: tracing::Level,
    /// From which interface to take the ip of the host
    #[arg(long)]
    interface: Option<String>,
    #[arg(long)]
    iptables_by_uname: Option<String>,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    queue_bypass: bool,
    #[arg(long, default_value_t = 8333)]
    bitcoin_port: u32,
    /// Stdout log level: error, warn, info, debug or trace, or a number 1-5
    #[arg(long, default_value_t = tracing::Level::INFO)]
    stdout_log: tracing::Level,
}

fn main() {
    let args = Args::parse();

    logging::setup_log(&args.log_template, args.log, args.stdout_log);

    let nodename = args.node_name;
    let dump_prefix = format!("capture_{}", nodename);

    let _configured_iptables;
    if let Some(uname) = args.iptables_by_uname {
        _configured_iptables =
            iptables::config_by_user(args.queue_num, args.queue_bypass, &uname, args.bitcoin_port);
    }

    let interceptor_opts = SlappNfqNetOptions {
        queue_num: args.queue_num,
        max_queue_len: args.max_queue_len,
    };

    let dumper_opts = DumperOptions {
        path_prefix: dump_prefix,
    };

    let running = Arc::new(AtomicBool::new(true));
    set_ctrlc_handler(&running);

    let host_ip = args.interface.map(|iface| {
        let ips = interface_ipv4_ips(&iface);
        if ips.is_empty() {
            panic!("Interface has too many ips");
        }

        let host_ip = ips[0];
        debug!("ip of interface {}: {}", iface, host_ip);

        host_ip.octets()
    });

    run_program(interceptor_opts, dumper_opts, running, host_ip).unwrap();
}
