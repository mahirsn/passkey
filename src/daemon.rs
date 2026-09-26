use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

const REQ: u8 = 0x10;
const CANCEL: u8 = 0x11;
const PING: u8 = 0x12;
const RESP: u8 = 0x20;
const PONG: u8 = 0x22;
const BT_UUID: &str = "7a1b6b65-7900-4e6f-9d2a-6d6168697273";
const BT_CHANNEL: u16 = 27;
const STATE: &str = "/run/passkey";

const UHID_DESTROY: u32 = 1;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;
const UHID_EVENT_SIZE: usize = 4 + 4372;
const REPORT_DESC: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

const PING_CMD: u8 = 0x81;
const INIT: u8 = 0x86;
const WINK: u8 = 0x88;
const CBOR: u8 = 0x90;
const CANCEL_CMD: u8 = 0x91;
const KEEPALIVE: u8 = 0xbb;
const ERROR: u8 = 0xbf;
const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;
const ERR_CHANNEL_BUSY: u8 = 0x06;
const ERR_INVALID_CHANNEL: u8 = 0x0b;
const CTAP2_ERR_OTHER: u8 = 0x7f;
const GET_ASSERTION: u8 = 0x02;
const GET_INFO: u8 = 0x04;
const GET_NEXT_ASSERTION: u8 = 0x08;
const OPERATION_DENIED: u8 = 0x27;
const NO_CREDENTIALS: u8 = 0x2e;
const BROADCAST: u32 = u32::MAX;

const SDP_RECORD: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001"><sequence><uuid value="7a1b6b65-7900-4e6f-9d2a-6d6168697273" /></sequence></attribute>
  <attribute id="0x0004"><sequence>
    <sequence><uuid value="0x0100" /></sequence>
    <sequence><uuid value="0x0003" /><uint8 value="0x1b" /></sequence>
  </sequence></attribute>
  <attribute id="0x0005"><sequence><uuid value="0x1002" /></sequence></attribute>
  <attribute id="0x0100"><text value="passkey" /></attribute>
</record>"#;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(STATE)?;
    let daemon = Arc::new(Daemon::new());
    for task in [adb_loop as fn(Arc<Daemon>), keepalive_loop, bluetooth_loop] {
        let daemon = daemon.clone();
        thread::spawn(move || task(daemon));
    }
    loop {
        thread::park();
    }
}

enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
        }
    }

    fn shutdown(&self) {
        let _ = match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            Self::Unix(stream) => stream.shutdown(Shutdown::Both),
        };
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Unix(stream) => stream.read(buffer),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Unix(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Unix(stream) => stream.flush(),
        }
    }
}

struct Link {
    name: String,
    device: String,
    label: String,
    priority: u8,
    writer: Mutex<Stream>,
    responses: Mutex<mpsc::Receiver<(u32, Vec<u8>)>>,
    response_tx: mpsc::Sender<(u32, Vec<u8>)>,
    pong: (Mutex<bool>, Condvar),
    alive: AtomicBool,
}

impl Link {
    fn new(
        name: String,
        stream: Stream,
        priority: u8,
        label: String,
        device: String,
    ) -> io::Result<Arc<Self>> {
        let (response_tx, responses) = mpsc::channel();
        Ok(Arc::new(Self {
            name,
            device,
            label: label.split_whitespace().collect::<Vec<_>>().join(" "),
            priority,
            writer: Mutex::new(stream),
            responses: Mutex::new(responses),
            response_tx,
            pong: (Mutex::new(false), Condvar::new()),
            alive: AtomicBool::new(true),
        }))
    }

    fn send(&self, body: &[u8]) -> io::Result<()> {
        let mut stream = self.writer.lock().unwrap();
        stream.write_all(&frame(body))
    }

    fn close(&self) {
        if self.alive.swap(false, Ordering::SeqCst) {
            self.writer.lock().unwrap().shutdown();
            let _ = self.response_tx.send((0, Vec::new()));
        }
    }

    fn ping(&self) -> bool {
        *self.pong.0.lock().unwrap() = false;
        if self.send(&[PING]).is_err() {
            return false;
        }
        let guard = self.pong.0.lock().unwrap();
        *self
            .pong
            .1
            .wait_timeout_while(guard, Duration::from_secs(10), |value| !*value)
            .unwrap()
            .0
    }
}

struct Partial {
    command: u8,
    total: usize,
    data: Vec<u8>,
    next_sequence: u8,
}

struct Request {
    channel: u32,
    number: u32,
    pending: Mutex<Vec<Arc<Link>>>,
}

type Answers = (Vec<(Arc<Link>, Vec<u8>)>, Vec<Vec<u8>>);

struct HidState {
    partial: HashMap<u32, Partial>,
    busy: Option<Arc<Request>>,
    holders: HashSet<String>,
    last: Option<String>,
}

struct UhidState {
    generation: u64,
    file: Option<File>,
}

struct Daemon {
    links: Mutex<Vec<Arc<Link>>>,
    hid: Mutex<HidState>,
    uhid: Mutex<UhidState>,
    next_request: AtomicU32,
    next_channel: AtomicU32,
    next_generation: AtomicU64,
}

impl Daemon {
    fn new() -> Self {
        Self {
            links: Mutex::new(Vec::new()),
            hid: Mutex::new(HidState {
                partial: HashMap::new(),
                busy: None,
                holders: HashSet::new(),
                last: None,
            }),
            uhid: Mutex::new(UhidState {
                generation: 0,
                file: None,
            }),
            next_request: AtomicU32::new(1),
            next_channel: AtomicU32::new(std::process::id().max(1)),
            next_generation: AtomicU64::new(1),
        }
    }

    fn add(self: &Arc<Self>, link: Arc<Link>) -> io::Result<()> {
        let mut reader = link.writer.lock().unwrap().try_clone()?;
        self.links.lock().unwrap().push(link.clone());
        self.publish();
        self.sync_uhid();
        println!(
            "connected: {} {} device {}",
            link.name, link.label, link.device
        );
        let daemon = self.clone();
        thread::spawn(move || {
            let result = read_link(&link, &mut reader);
            if let Err(error) = result {
                eprintln!("{} read ended: {error}", link.name);
            }
            link.close();
            daemon.remove(&link);
        });
        Ok(())
    }

    fn remove(self: &Arc<Self>, link: &Arc<Link>) {
        let mut links = self.links.lock().unwrap();
        let before = links.len();
        links.retain(|candidate| !Arc::ptr_eq(candidate, link));
        drop(links);
        if before != self.links.lock().unwrap().len() {
            println!("disconnected: {}", link.name);
            self.publish();
            self.sync_uhid();
        }
    }

    fn publish(&self) {
        let mut links = self
            .links
            .lock()
            .unwrap()
            .iter()
            .filter(|link| link.alive.load(Ordering::SeqCst))
            .cloned()
            .collect::<Vec<_>>();
        links.sort_by_key(|link| link.priority);
        let mut seen = HashSet::new();
        let mut text = String::new();
        for link in links {
            if seen.insert(link.device.clone()) {
                text.push_str(&format!("{}\t{}\n", link.device, link.label));
            }
        }
        if let Err(error) = atomic_write(&Path::new(STATE).join("devices"), text.as_bytes()) {
            eprintln!("state: {error}");
        }
    }

    fn live_links(&self) -> Vec<Arc<Link>> {
        self.links
            .lock()
            .unwrap()
            .iter()
            .filter(|link| link.alive.load(Ordering::SeqCst))
            .cloned()
            .collect()
    }

    fn by_device(&self) -> HashMap<String, Arc<Link>> {
        let mut links = self.live_links();
        links.sort_by_key(|link| link.priority);
        let mut devices = HashMap::new();
        for link in links {
            devices.entry(link.device.clone()).or_insert(link);
        }
        devices
    }

    fn sync_uhid(self: &Arc<Self>) {
        if self.live_links().is_empty() {
            self.cancel(None, false);
            self.destroy_uhid();
        } else if let Err(error) = self.create_uhid() {
            eprintln!("uhid: {error}");
        }
    }

    fn create_uhid(self: &Arc<Self>) -> io::Result<()> {
        let mut state = self.uhid.lock().unwrap();
        if state.file.is_some() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")?;
        let mut event = vec![0_u8; UHID_EVENT_SIZE];
        put_u32_le(&mut event, 0, UHID_CREATE2);
        event[4..11].copy_from_slice(b"passkey");
        put_u16_le(&mut event, 260, REPORT_DESC.len() as u16);
        put_u16_le(&mut event, 262, 0x03);
        put_u32_le(&mut event, 264, 0x1209);
        put_u32_le(&mut event, 268, 0x7ab1);
        put_u32_le(&mut event, 272, 1);
        event[280..280 + REPORT_DESC.len()].copy_from_slice(REPORT_DESC);
        file.write_all(&event)?;
        let reader = file.try_clone()?;
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        state.generation = generation;
        state.file = Some(file);
        drop(state);
        println!("FIDO device added");
        let daemon = self.clone();
        thread::spawn(move || daemon.read_uhid(generation, reader));
        Ok(())
    }

    fn destroy_uhid(&self) {
        let mut state = self.uhid.lock().unwrap();
        if let Some(mut file) = state.file.take() {
            let mut event = vec![0_u8; UHID_EVENT_SIZE];
            put_u32_le(&mut event, 0, UHID_DESTROY);
            let _ = file.write_all(&event);
            state.generation = 0;
            println!("FIDO device removed");
        }
    }

    fn read_uhid(self: Arc<Self>, generation: u64, mut file: File) {
        self.read_uhid_events(generation, &mut file);
        drop(file);
        let mut state = self.uhid.lock().unwrap();
        if state.generation == generation {
            state.file = None;
            state.generation = 0;
            drop(state);
            self.sync_uhid();
        }
    }

    fn read_uhid_events(self: &Arc<Self>, generation: u64, file: &mut File) {
        let mut event = vec![0_u8; UHID_EVENT_SIZE + 16];
        loop {
            if self.uhid.lock().unwrap().generation != generation {
                return;
            }
            let mut poll = libc::pollfd {
                fd: file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 500) } <= 0 {
                continue;
            }
            let size = match file.read(&mut event) {
                Ok(0) | Err(_) => return,
                Ok(size) => size,
            };
            if size < 4 {
                continue;
            }
            match u32::from_le_bytes(event[..4].try_into().unwrap()) {
                UHID_OUTPUT if size >= 4102 => {
                    let count = u16::from_le_bytes(event[4100..4102].try_into().unwrap()) as usize;
                    let mut report = &event[4..4 + count.min(4096)];
                    if report.len() == 65 {
                        report = &report[1..];
                    }
                    self.packet(&report[..report.len().min(64)]);
                }
                UHID_CLOSE => self.cancel(None, false),
                kind @ (UHID_GET_REPORT | UHID_SET_REPORT) if size >= 8 => {
                    let id = u32::from_le_bytes(event[4..8].try_into().unwrap());
                    let reply = if kind == UHID_GET_REPORT {
                        UHID_GET_REPORT_REPLY
                    } else {
                        UHID_SET_REPORT_REPLY
                    };
                    let mut response = vec![0_u8; UHID_EVENT_SIZE];
                    put_u32_le(&mut response, 0, reply);
                    put_u32_le(&mut response, 4, id);
                    put_u16_le(&mut response, 8, 5);
                    self.write_uhid(&response);
                }
                _ => {}
            }
        }
    }

    fn write_uhid(&self, event: &[u8]) {
        if let Some(file) = self.uhid.lock().unwrap().file.as_mut() {
            let _ = file.write_all(event);
        }
    }

    fn send_report(&self, report: &[u8]) {
        let mut event = vec![0_u8; UHID_EVENT_SIZE];
        put_u32_le(&mut event, 0, UHID_INPUT2);
        put_u16_le(&mut event, 4, 64);
        event[6..6 + report.len().min(64)].copy_from_slice(&report[..report.len().min(64)]);
        self.write_uhid(&event);
    }

    fn reply(&self, channel: u32, command: u8, data: &[u8]) {
        let mut first = Vec::with_capacity(64);
        first.extend_from_slice(&channel.to_be_bytes());
        first.push(command);
        first.extend_from_slice(&(data.len() as u16).to_be_bytes());
        first.extend_from_slice(&data[..data.len().min(57)]);
        self.send_report(&first);
        let mut rest = &data[data.len().min(57)..];
        let mut sequence = 0_u8;
        while !rest.is_empty() {
            let count = rest.len().min(59);
            let mut packet = Vec::with_capacity(64);
            packet.extend_from_slice(&channel.to_be_bytes());
            packet.push(sequence);
            packet.extend_from_slice(&rest[..count]);
            self.send_report(&packet);
            rest = &rest[count..];
            sequence = sequence.wrapping_add(1);
        }
    }

    fn error(&self, channel: u32, code: u8) {
        self.reply(channel, ERROR, &[code]);
    }

    fn packet(self: &Arc<Self>, packet: &[u8]) {
        if packet.len() < 5 {
            return;
        }
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        let byte = packet[4];
        if byte & 0x80 != 0 {
            if packet.len() < 7 {
                return;
            }
            let total = u16::from_be_bytes(packet[5..7].try_into().unwrap()) as usize;
            if total > 7609 {
                self.error(channel, ERR_INVALID_LEN);
                return;
            }
            if byte == CANCEL_CMD {
                self.cancel(Some(channel), false);
                return;
            }
            if byte == INIT {
                self.hid.lock().unwrap().partial.remove(&channel);
                self.cancel(Some(channel), true);
            } else if self
                .hid
                .lock()
                .unwrap()
                .busy
                .as_ref()
                .is_some_and(|request| request.channel != channel)
            {
                self.error(channel, ERR_CHANNEL_BUSY);
                return;
            }
            self.hid.lock().unwrap().partial.insert(
                channel,
                Partial {
                    command: byte,
                    total,
                    data: packet[7..packet.len().min(7 + total)].to_vec(),
                    next_sequence: 0,
                },
            );
        } else {
            let mut hid = self.hid.lock().unwrap();
            let Some(partial) = hid.partial.get_mut(&channel) else {
                return;
            };
            if byte != partial.next_sequence {
                hid.partial.remove(&channel);
                drop(hid);
                self.error(channel, ERR_INVALID_SEQ);
                return;
            }
            let count = (partial.total - partial.data.len()).min(packet.len() - 5);
            partial.data.extend_from_slice(&packet[5..5 + count]);
            partial.next_sequence = partial.next_sequence.wrapping_add(1);
        }
        let complete = {
            let mut hid = self.hid.lock().unwrap();
            if hid
                .partial
                .get(&channel)
                .is_some_and(|partial| partial.data.len() >= partial.total)
            {
                hid.partial.remove(&channel)
            } else {
                None
            }
        };
        if let Some(partial) = complete {
            self.dispatch(channel, partial.command, partial.data);
        }
    }

    fn dispatch(self: &Arc<Self>, channel: u32, command: u8, data: Vec<u8>) {
        match command {
            INIT => {
                if data.len() != 8 {
                    self.error(channel, ERR_INVALID_LEN);
                    return;
                }
                let assigned = if channel == BROADCAST {
                    loop {
                        let candidate = self.next_channel.fetch_add(1, Ordering::Relaxed);
                        if candidate != 0 && candidate != BROADCAST {
                            break candidate;
                        }
                    }
                } else {
                    channel
                };
                let mut reply = data;
                reply.extend_from_slice(&assigned.to_be_bytes());
                reply.extend_from_slice(&[2, 1, 0, 0, 0x0d]);
                self.reply(channel, INIT, &reply);
            }
            _ if channel == 0 || channel == BROADCAST => self.error(channel, ERR_INVALID_CHANNEL),
            PING_CMD => self.reply(channel, PING_CMD, &data),
            WINK => self.reply(channel, WINK, &[]),
            _ if command != CBOR => self.error(channel, ERR_INVALID_CMD),
            _ if data.is_empty() || self.live_links().is_empty() => {
                self.reply(channel, CBOR, &[CTAP2_ERR_OTHER])
            }
            _ => {
                let request = Arc::new(Request {
                    channel,
                    number: self.next_request.fetch_add(1, Ordering::Relaxed),
                    pending: Mutex::new(Vec::new()),
                });
                let mut hid = self.hid.lock().unwrap();
                if hid.busy.is_some() {
                    drop(hid);
                    self.error(channel, ERR_CHANNEL_BUSY);
                    return;
                }
                hid.busy = Some(request.clone());
                drop(hid);
                let daemon = self.clone();
                thread::spawn(move || daemon.handle_cbor(request, data));
            }
        }
    }

    fn cancel(&self, channel: Option<u32>, abandon: bool) {
        let request = {
            let mut hid = self.hid.lock().unwrap();
            let request = hid.busy.clone();
            if abandon
                && request
                    .as_ref()
                    .is_some_and(|request| Some(request.channel) == channel)
            {
                hid.busy = None;
            }
            request
        };
        if let Some(request) = request
            && channel.is_none_or(|channel| channel == request.channel)
        {
            withdraw(&request, &request.pending.lock().unwrap());
        }
    }

    fn request_is_current(&self, request: &Arc<Request>) -> bool {
        self.hid
            .lock()
            .unwrap()
            .busy
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, request))
    }

    fn handle_cbor(self: Arc<Self>, request: Arc<Request>, data: Vec<u8>) {
        let devices = self.by_device();
        let chosen = chosen_device();
        let probe = silent(&data);
        let (holders, last) = {
            let hid = self.hid.lock().unwrap();
            (hid.holders.clone(), hid.last.clone())
        };
        let all = devices.values().cloned().collect::<Vec<_>>();
        let rounds: Vec<Vec<Arc<Link>>> = if let Some(chosen) = chosen {
            vec![devices.get(&chosen).cloned().into_iter().collect()]
        } else if data[0] == GET_INFO {
            vec![all.into_iter().take(1).collect()]
        } else if data[0] == GET_NEXT_ASSERTION {
            vec![
                last.and_then(|device| devices.get(&device).cloned())
                    .into_iter()
                    .collect(),
            ]
        } else if data[0] == GET_ASSERTION
            && !probe
            && holders.iter().any(|device| devices.contains_key(device))
        {
            let first = all
                .iter()
                .filter(|link| holders.contains(&link.device))
                .cloned()
                .collect::<Vec<_>>();
            let rest = all
                .into_iter()
                .filter(|link| !holders.contains(&link.device))
                .collect();
            vec![first, rest]
        } else {
            vec![all]
        };

        let deadline = Instant::now() + Duration::from_secs(600);
        let mut errors = Vec::new();
        for targets in rounds {
            if targets.is_empty() {
                continue;
            }
            let (wins, mut failures) = self.fan_out(&request, targets, &data, deadline, probe);
            if let Some((winner, payload)) = wins.first() {
                if data[0] == GET_ASSERTION {
                    let mut hid = self.hid.lock().unwrap();
                    hid.last = Some(winner.device.clone());
                    if probe {
                        hid.holders = wins.iter().map(|(link, _)| link.device.clone()).collect();
                    }
                }
                if self.request_is_current(&request) {
                    self.reply(request.channel, CBOR, payload);
                }
                self.finish_request(&request);
                return;
            }
            let should_stop = !failures.is_empty()
                && failures
                    .iter()
                    .any(|error| error.first() != Some(&NO_CREDENTIALS));
            errors.append(&mut failures);
            if should_stop {
                break;
            }
        }
        let final_error = errors
            .iter()
            .find(|error| error.first() != Some(&NO_CREDENTIALS))
            .or_else(|| errors.first())
            .cloned()
            .unwrap_or_else(|| vec![CTAP2_ERR_OTHER]);
        if self.request_is_current(&request) {
            self.reply(request.channel, CBOR, &final_error);
        }
        self.finish_request(&request);
    }

    fn finish_request(&self, request: &Arc<Request>) {
        let mut hid = self.hid.lock().unwrap();
        if hid
            .busy
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, request))
        {
            hid.busy = None;
        }
    }

    fn fan_out(
        &self,
        request: &Arc<Request>,
        targets: Vec<Arc<Link>>,
        data: &[u8],
        deadline: Instant,
        wait_all: bool,
    ) -> Answers {
        let mut pending = Vec::new();
        let mut message = Vec::with_capacity(5 + data.len());
        message.push(REQ);
        message.extend_from_slice(&request.number.to_be_bytes());
        message.extend_from_slice(data);
        for link in targets {
            if link.send(&message).is_ok() {
                pending.push(link);
            }
        }
        *request.pending.lock().unwrap() = pending.clone();
        let mut wins = Vec::new();
        let mut errors = Vec::new();
        let mut last_beat = Instant::now() - Duration::from_secs(1);
        let mut done = false;
        while !pending.is_empty()
            && !done
            && Instant::now() < deadline
            && self.request_is_current(request)
        {
            let mut heard = false;
            for link in pending.clone() {
                let response = link.responses.lock().unwrap().try_recv();
                let Ok((number, payload)) = response else {
                    continue;
                };
                heard = true;
                if number == 0 && payload.is_empty() {
                    pending.retain(|candidate| !Arc::ptr_eq(candidate, &link));
                    errors.push(vec![CTAP2_ERR_OTHER]);
                    continue;
                }
                if number != request.number {
                    continue;
                }
                pending.retain(|candidate| !Arc::ptr_eq(candidate, &link));
                if payload.is_empty() {
                    errors.push(vec![CTAP2_ERR_OTHER]);
                } else if payload[0] == 0 {
                    wins.push((link, payload));
                    done = !wait_all;
                } else {
                    done = payload[0] == OPERATION_DENIED && !wait_all;
                    errors.push(payload);
                }
                if done {
                    break;
                }
            }
            if !heard {
                if last_beat.elapsed() >= Duration::from_millis(100) {
                    self.reply(request.channel, KEEPALIVE, &[2]);
                    last_beat = Instant::now();
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        request.pending.lock().unwrap().clear();
        withdraw(request, &pending);
        (wins, errors)
    }
}

fn read_link(link: &Arc<Link>, stream: &mut Stream) -> io::Result<()> {
    loop {
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(1..=8192).contains(&length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame length {length}"),
            ));
        }
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body)?;
        match body[0] {
            RESP if body.len() >= 5 => {
                let (number, payload) = decode_response(&body).unwrap();
                let _ = link.response_tx.send((number, payload.to_vec()));
            }
            PONG => {
                *link.pong.0.lock().unwrap() = true;
                link.pong.1.notify_all();
            }
            _ => {}
        }
    }
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(body);
    framed
}

fn decode_response(body: &[u8]) -> Option<(u32, &[u8])> {
    (body.first() == Some(&RESP) && body.len() >= 5).then(|| {
        (
            u32::from_be_bytes(body[1..5].try_into().unwrap()),
            &body[5..],
        )
    })
}

fn withdraw(request: &Request, links: &[Arc<Link>]) {
    let mut message = vec![CANCEL];
    message.extend_from_slice(&request.number.to_be_bytes());
    for link in links {
        let _ = link.send(&message);
    }
}

fn keepalive_loop(daemon: Arc<Daemon>) {
    loop {
        thread::sleep(Duration::from_secs(20));
        for link in daemon.live_links() {
            if !link.ping() {
                eprintln!("no answer: {}", link.name);
                link.close();
            }
        }
    }
}

fn adb_loop(daemon: Arc<Daemon>) {
    if std::env::var("PASSKEY_NO_USB").as_deref() == Ok("1") {
        return;
    }
    let mut retry = HashMap::<String, Instant>::new();
    let mut last_start = Instant::now() - Duration::from_secs(61);
    loop {
        let serials = if adb_server_trusted() {
            adb_devices().unwrap_or_default()
        } else {
            if last_start.elapsed() > Duration::from_secs(60) {
                last_start = Instant::now();
                adb_start_server();
            }
            Vec::new()
        };
        let names = daemon
            .live_links()
            .into_iter()
            .map(|link| link.name.clone())
            .collect::<HashSet<_>>();
        for serial in serials {
            let name = format!("usb:{serial}");
            if names.contains(&name)
                || retry
                    .get(&serial)
                    .is_some_and(|until| *until > Instant::now())
            {
                continue;
            }
            if let Ok(mut stream) = adb_request(&format!("host:transport:{serial}"), None)
                && adb_request(
                    &format!("localabstract:{}", adb_socket()),
                    Some(&mut stream),
                )
                .is_ok()
            {
                let mut ping = Vec::from(1_u32.to_be_bytes());
                ping.push(PING);
                if stream.write_all(&ping).is_ok() {
                    let mut pong = [0_u8; 5];
                    if stream.read_exact(&mut pong).is_ok() && pong == [0, 0, 0, 1, PONG] {
                        let label = adb_setting(&serial, "global device_name").unwrap_or_default();
                        let device = adb_device_id(&serial);
                        // Discovery is bounded; the established Android link stays idle between requests.
                        if stream.set_read_timeout(None).is_err() {
                            continue;
                        }
                        let link = Link::new(name, Stream::Tcp(stream), 0, label, device);
                        if let Ok(link) = link
                            && daemon.add(link).is_ok()
                        {
                            retry.remove(&serial);
                            continue;
                        }
                    }
                }
            }
            retry.insert(serial, Instant::now() + Duration::from_secs(10));
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn adb_socket() -> String {
    std::env::var("PASSKEY_SOCKET").unwrap_or_else(|_| "passkey".into())
}

fn adb_start_server() {
    let mut command = if unsafe { libc::geteuid() } == 0 {
        if let Ok(user) = std::env::var("PASSKEY_ADB_USER")
            && !user.is_empty()
        {
            let mut command = Command::new("runuser");
            command.args(["-u", &user, "--", "adb"]);
            command
        } else {
            Command::new("adb")
        }
    } else {
        Command::new("adb")
    };
    let _ = command.arg("start-server").output();
}

fn allowed_adb_uids() -> HashSet<u32> {
    let mut allowed = HashSet::from([0, unsafe { libc::geteuid() }]);
    if let Ok(user) = std::env::var("PASSKEY_ADB_USER")
        && let Ok(user) = std::ffi::CString::new(user)
    {
        let entry = unsafe { libc::getpwnam(user.as_ptr()) };
        if !entry.is_null() {
            allowed.insert(unsafe { (*entry).pw_uid });
        }
    }
    allowed
}

fn adb_server_trusted() -> bool {
    proc_tcp().is_some_and(|rows| {
        rows.iter().any(|row| {
            matches!(row.local.as_str(), "0100007F:13AD" | "00000000:13AD")
                && row.state == "0A"
                && allowed_adb_uids().contains(&row.uid)
        })
    })
}

fn adb_peer_trusted(stream: &TcpStream) -> bool {
    let Ok(local) = stream.local_addr() else {
        return false;
    };
    let IpAddr::V4(ip) = local.ip() else {
        return false;
    };
    let ours = format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(ip.octets()),
        local.port()
    );
    proc_tcp().is_some_and(|rows| {
        rows.iter().any(|row| {
            row.local == "0100007F:13AD"
                && row.remote == ours
                && allowed_adb_uids().contains(&row.uid)
        })
    })
}

struct TcpRow {
    local: String,
    remote: String,
    state: String,
    uid: u32,
}

fn proc_tcp() -> Option<Vec<TcpRow>> {
    let text = fs::read_to_string("/proc/net/tcp").ok()?;
    Some(
        text.lines()
            .skip(1)
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                Some(TcpRow {
                    local: fields.get(1)?.to_string(),
                    remote: fields.get(2)?.to_string(),
                    state: fields.get(3)?.to_string(),
                    uid: fields.get(7)?.parse().ok()?,
                })
            })
            .collect(),
    )
}

fn adb_request(service: &str, stream: Option<&mut TcpStream>) -> io::Result<TcpStream> {
    let mut owned;
    let stream = if let Some(stream) = stream {
        stream
    } else {
        owned =
            TcpStream::connect_timeout(&"127.0.0.1:5037".parse().unwrap(), Duration::from_secs(3))?;
        owned.set_read_timeout(Some(Duration::from_secs(3)))?;
        if !adb_peer_trusted(&owned) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted adb server",
            ));
        }
        &mut owned
    };
    stream.write_all(format!("{:04x}{service}", service.len()).as_bytes())?;
    let mut status = [0_u8; 4];
    stream.read_exact(&mut status)?;
    if &status != b"OKAY" {
        return Err(io::Error::other(format!("adb rejected {service}")));
    }
    stream.try_clone()
}

fn adb_devices() -> io::Result<Vec<String>> {
    let mut stream = adb_request("host:devices", None)?;
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length =
        usize::from_str_radix(std::str::from_utf8(&length).unwrap_or("0"), 16).unwrap_or(0);
    let mut data = vec![0_u8; length];
    stream.read_exact(&mut data)?;
    Ok(String::from_utf8_lossy(&data)
        .lines()
        .filter_map(|line| line.strip_suffix("\tdevice"))
        .map(str::to_owned)
        .collect())
}

fn adb_setting(serial: &str, setting: &str) -> io::Result<String> {
    let mut stream = adb_request(&format!("host:transport:{serial}"), None)?;
    adb_request(&format!("shell:settings get {setting}"), Some(&mut stream))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut output = String::new();
    stream.read_to_string(&mut output)?;
    let output = output.trim().to_string();
    Ok(if output == "null" {
        String::new()
    } else {
        output
    })
}

fn adb_device_id(serial: &str) -> String {
    let address = adb_setting(serial, "secure bluetooth_address")
        .unwrap_or_default()
        .to_uppercase();
    if is_bt_address(&address) {
        address
    } else {
        format!("usb:{serial}")
    }
}

fn is_bt_address(value: &str) -> bool {
    let fields = value.split(':').collect::<Vec<_>>();
    fields.len() == 6
        && fields
            .iter()
            .all(|field| field.len() == 2 && field.chars().all(|c| c.is_ascii_hexdigit()))
}

struct Profile {
    daemon: Arc<Daemon>,
    connection: Connection,
}

#[zbus::interface(name = "org.bluez.Profile1")]
impl Profile {
    fn release(&self) {}

    fn new_connection(
        &self,
        device: OwnedObjectPath,
        fd: zbus::zvariant::OwnedFd,
        _properties: HashMap<String, OwnedValue>,
    ) {
        let daemon = self.daemon.clone();
        let connection = self.connection.clone();
        let device_path = device.to_string();
        thread::spawn(move || {
            let address = device_path
                .rsplit_once("dev_")
                .map(|(_, value)| value.replace('_', ":"))
                .unwrap_or_else(|| device_path.clone());
            let label =
                bluetooth_alias(&connection, &device_path).unwrap_or_else(|| address.clone());
            let fd: OwnedFd = fd.into();
            let stream = UnixStream::from(fd);
            if let Ok(link) = Link::new(
                format!("bt:{address}"),
                Stream::Unix(stream),
                1,
                label,
                address,
            ) {
                let _ = daemon.add(link);
            }
        });
    }

    fn request_disconnection(&self, device: OwnedObjectPath) {
        let address = device
            .to_string()
            .rsplit_once("dev_")
            .map(|(_, value)| value.replace('_', ":"));
        if let Some(address) = address {
            for link in self.daemon.live_links() {
                if link.name == format!("bt:{address}") {
                    link.close();
                }
            }
        }
    }
}

fn bluetooth_loop(daemon: Arc<Daemon>) {
    loop {
        if let Err(error) = bluetooth_session(daemon.clone()) {
            eprintln!("bluetooth: {error}");
        }
        thread::sleep(Duration::from_secs(10));
    }
}

fn bluetooth_session(daemon: Arc<Daemon>) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::system()?;
    connection.object_server().at(
        "/sn/mahir/passkey",
        Profile {
            daemon,
            connection: connection.clone(),
        },
    )?;
    let proxy = Proxy::new(
        &connection,
        "org.bluez",
        "/org/bluez",
        "org.bluez.ProfileManager1",
    )?;
    loop {
        let mut options = HashMap::<&str, Value<'_>>::new();
        options.insert("Name", Value::from("passkey"));
        options.insert("Role", Value::from("server"));
        options.insert("Channel", Value::from(BT_CHANNEL));
        options.insert("ServiceRecord", Value::from(SDP_RECORD));
        options.insert("RequireAuthentication", Value::from(true));
        options.insert("RequireAuthorization", Value::from(false));
        options.insert("AutoConnect", Value::from(false));
        let path = ObjectPath::try_from("/sn/mahir/passkey")?;
        match proxy.call::<_, _, ()>("RegisterProfile", &(path, BT_UUID, options)) {
            Ok(()) => println!("bluetooth: listening"),
            Err(error) if error.to_string().contains("AlreadyExists") => {}
            Err(error) => eprintln!("bluetooth: not registered: {error}"),
        }
        thread::sleep(Duration::from_secs(10));
    }
}

fn bluetooth_alias(connection: &Connection, path: &str) -> Option<String> {
    let proxy = Proxy::new(
        connection,
        "org.bluez",
        path,
        "org.freedesktop.DBus.Properties",
    )
    .ok()?;
    let value: OwnedValue = proxy.call("Get", &("org.bluez.Device1", "Alias")).ok()?;
    String::try_from(value).ok()
}

fn chosen_device() -> Option<String> {
    let text = fs::read_to_string(format!("{STATE}/use")).ok()?;
    let mut fields = text.split_whitespace();
    let device = fields.next()?.to_string();
    let pid = fields.next()?.parse::<u32>().ok()?;
    Path::new(&format!("/proc/{pid}"))
        .exists()
        .then_some(device)
}

fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("new");
    fs::write(&temporary, data)?;
    fs::rename(temporary, path)
}

fn put_u16_le(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_le(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Debug, PartialEq)]
enum Cbor {
    Integer(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

fn decode_cbor(input: &[u8], offset: &mut usize, depth: usize) -> Result<Cbor, ()> {
    if depth > 8 || *offset >= input.len() {
        return Err(());
    }
    let first = input[*offset];
    *offset += 1;
    let major = first >> 5;
    let info = first & 31;
    if major == 7 {
        return match info {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 => Ok(Cbor::Null),
            _ => Err(()),
        };
    }
    let value = match info {
        0..=23 => info as u64,
        24 => read_uint(input, offset, 1)?,
        25 => read_uint(input, offset, 2)?,
        26 => read_uint(input, offset, 4)?,
        27 => read_uint(input, offset, 8)?,
        _ => return Err(()),
    };
    match major {
        0 => i64::try_from(value).map(Cbor::Integer).map_err(|_| ()),
        1 => i64::try_from(value)
            .map(|value| Cbor::Integer(-1 - value))
            .map_err(|_| ()),
        2 | 3 => {
            let length = usize::try_from(value).map_err(|_| ())?;
            let end = offset.checked_add(length).ok_or(())?;
            let bytes = input.get(*offset..end).ok_or(())?;
            *offset = end;
            if major == 2 {
                Ok(Cbor::Bytes(bytes.to_vec()))
            } else {
                String::from_utf8(bytes.to_vec())
                    .map(Cbor::Text)
                    .map_err(|_| ())
            }
        }
        4 => {
            let mut values = Vec::new();
            for _ in 0..value {
                values.push(decode_cbor(input, offset, depth + 1)?);
            }
            Ok(Cbor::Array(values))
        }
        5 => {
            let mut values = Vec::new();
            for _ in 0..value {
                values.push((
                    decode_cbor(input, offset, depth + 1)?,
                    decode_cbor(input, offset, depth + 1)?,
                ));
            }
            Ok(Cbor::Map(values))
        }
        6 => decode_cbor(input, offset, depth + 1),
        _ => Err(()),
    }
}

fn read_uint(input: &[u8], offset: &mut usize, count: usize) -> Result<u64, ()> {
    let end = offset.checked_add(count).ok_or(())?;
    let bytes = input.get(*offset..end).ok_or(())?;
    *offset = end;
    Ok(bytes
        .iter()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
}

fn silent(data: &[u8]) -> bool {
    if data.first() != Some(&GET_ASSERTION) {
        return false;
    }
    let Ok(Cbor::Map(root)) = decode_cbor(data, &mut 1, 0) else {
        return false;
    };
    root.into_iter().any(|(key, value)| {
        if key != Cbor::Integer(5) {
            return false;
        }
        let Cbor::Map(options) = value else {
            return false;
        };
        options
            .into_iter()
            .any(|(key, value)| key == Cbor::Text("up".into()) && value == Cbor::Bool(false))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_presence_free_get_assertion() {
        // command 2, map {5: {"up": false}}
        assert!(silent(&[0x02, 0xa1, 0x05, 0xa1, 0x62, b'u', b'p', 0xf4]));
        assert!(!silent(&[0x02, 0xa1, 0x05, 0xa1, 0x62, b'u', b'p', 0xf5]));
        assert!(!silent(&[0x04]));
    }

    #[test]
    fn validates_bluetooth_addresses() {
        assert!(is_bt_address("AA:BB:CC:DD:EE:FF"));
        assert!(!is_bt_address("usb:serial"));
    }

    #[test]
    fn exchanges_android_wire_frames() {
        assert_eq!(
            frame(&[REQ, 0, 0, 0, 7, GET_INFO]),
            [0, 0, 0, 6, REQ, 0, 0, 0, 7, GET_INFO]
        );
        assert_eq!(decode_response(&[RESP, 0, 0, 0, 7, 0]), Some((7, &[0][..])));
        assert_eq!(decode_response(&[RESP, 0]), None);
    }
}
