//! Direct LAN transport. Pairing pins the phone's certificate before sending its secret.
use openssl::hash::MessageDigest;
use openssl::ssl::{ErrorCode, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DIRECTORY: &str = "/etc/passkey/wifi";
pub const PORT: u16 = 40719;
const MAGIC: &[u8] = b"PASSKEY-WIFI-1\n";

#[derive(Clone)]
pub struct Peer {
    pub address: SocketAddr,
    pub pin: [u8; 32],
    secret: [u8; 32],
}

impl Peer {
    pub fn parse(address: &str, code: &str) -> io::Result<Self> {
        let address = endpoint(address)?;
        let fields = code.trim().split(':').collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "pk1" {
            return Err(invalid(
                "expected the pk1:... pairing code copied from the phone",
            ));
        }
        Ok(Self {
            address,
            pin: unhex(fields[1])?,
            secret: unhex(fields[2])?,
        })
    }

    pub fn id(&self) -> String {
        hex(&self.pin)
    }
    pub fn encode(&self) -> String {
        format!(
            "{}\npk1:{}:{}\n",
            self.address,
            self.id(),
            hex(&self.secret)
        )
    }
    pub fn decode(text: &str) -> io::Result<Self> {
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 2 {
            return Err(invalid("invalid Wi-Fi profile"));
        }
        Self::parse(lines[0], lines[1])
    }

    pub fn connect(&self) -> io::Result<(TlsStream, String)> {
        let tcp = TcpStream::connect_timeout(&self.address, Duration::from_secs(4))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).map_err(io::Error::other)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(io::Error::other)?;
        // This is a private, self-signed identity: the copied certificate pin replaces Web PKI.
        builder.set_verify(SslVerifyMode::NONE);
        let mut stream = builder
            .build()
            .connect("passkey.wifi", tcp)
            .map_err(io::Error::other)?;
        let certificate = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| invalid("missing phone certificate"))?;
        let digest = certificate
            .digest(MessageDigest::sha256())
            .map_err(io::Error::other)?;
        if !openssl::memcmp::eq(digest.as_ref(), &self.pin) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "phone certificate does not match the pairing code",
            ));
        }
        stream.write_all(MAGIC)?;
        stream.write_all(&self.secret)?;
        let mut ack = [0; 5];
        stream.read_exact(&mut ack)?;
        if ack != [0, 0, 0, 1, 0x22] {
            return Err(invalid("phone rejected Wi-Fi authentication"));
        }
        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let size = u16::from_be_bytes(length) as usize;
        if !(1..=256).contains(&size) {
            return Err(invalid("invalid phone name length"));
        }
        let mut label = vec![0; size];
        stream.read_exact(&mut label)?;
        let label = String::from_utf8(label).map_err(|_| invalid("invalid phone name"))?;
        let label = label
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();
        stream.get_ref().set_read_timeout(None)?;
        stream.get_ref().set_write_timeout(None)?;
        stream.get_ref().set_nonblocking(true)?;
        Ok((
            TlsStream(Arc::new(Mutex::new(stream))),
            format!("{label} (Wi-Fi)"),
        ))
    }
}

pub fn endpoint(value: &str) -> io::Result<SocketAddr> {
    let address = value
        .parse::<SocketAddr>()
        .or_else(|_| value.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, PORT)))
        .map_err(|_| invalid("use the phone's local IP address, optionally followed by :40719"))?;
    let local = match address.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_loopback(),
    };
    if !local || address.port() == 0 {
        return Err(invalid(
            "Wi-Fi requires a private/local IP address and a nonzero port",
        ));
    }
    Ok(address)
}

pub fn load() -> io::Result<Vec<Peer>> {
    load_from(Path::new(DIRECTORY))
}
fn load_from(directory: &Path) -> io::Result<Vec<Peer>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut peers = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.path().extension().is_none_or(|ext| ext != "conf") {
            continue;
        }
        let meta = entry.path().symlink_metadata()?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.len() > 512 {
            return Err(invalid(
                "Wi-Fi profiles must be root-owned regular files with mode 0600",
            ));
        }
        peers.push(Peer::decode(&fs::read_to_string(entry.path())?)?);
    }
    Ok(peers)
}

pub fn save(peer: &Peer) -> io::Result<()> {
    fs::create_dir_all(DIRECTORY)?;
    fs::set_permissions(DIRECTORY, fs::Permissions::from_mode(0o700))?;
    let path = Path::new(DIRECTORY).join(format!("{}.conf", peer.id()));
    let temp = path.with_extension(format!("{}.new", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(peer.encode().as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    let _ = fs::remove_file(temp);
    result
}

pub fn remove(address: &str) -> io::Result<()> {
    let address = endpoint(address)?;
    let mut found = false;
    for peer in load()? {
        if peer.address == address {
            fs::remove_file(Path::new(DIRECTORY).join(format!("{}.conf", peer.id())))?;
            found = true;
        }
    }
    if !found {
        return Err(invalid("no paired phone at that address"));
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            "pairing code must contain two 32-byte hexadecimal values",
        ));
    }
    let mut output = [0; 32];
    for (i, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| invalid("invalid pairing code"))?;
    }
    Ok(output)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// A shared nonblocking TLS session lets CANCEL and PING pass while the reader waits.
#[derive(Clone)]
pub struct TlsStream(Arc<Mutex<SslStream<TcpStream>>>);
impl TlsStream {
    pub fn shutdown(&self) {
        let _ = self.0.lock().unwrap().get_ref().shutdown(Shutdown::Both);
    }
    fn wait(&self, code: ErrorCode, timeout: i32) -> io::Result<()> {
        if code != ErrorCode::WANT_READ && code != ErrorCode::WANT_WRITE {
            return Err(invalid("TLS connection failed"));
        }
        let fd = self.0.lock().unwrap().get_ref().as_raw_fd();
        let mut poll = libc::pollfd {
            fd,
            events: if code == ErrorCode::WANT_READ {
                libc::POLLIN
            } else {
                libc::POLLOUT
            },
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut poll, 1, timeout) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS write timed out",
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
impl Read for TlsStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let result = self.0.lock().unwrap().ssl_read(buffer);
            match result {
                Ok(n) => return Ok(n),
                Err(e) if e.code() == ErrorCode::ZERO_RETURN => return Ok(0),
                Err(e) => self.wait(e.code(), -1)?,
            }
        }
    }
}
impl Write for TlsStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            let result = self.0.lock().unwrap().ssl_write(buffer);
            match result {
                Ok(n) => return Ok(n),
                Err(e) => self.wait(e.code(), 5000)?,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::ssl::SslAcceptor;
    use openssl::x509::{X509, X509NameBuilder};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn server(
        handler: impl FnOnce(SslStream<TcpStream>) + Send + 'static,
    ) -> (Peer, thread::JoinHandle<()>) {
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "passkey.wifi").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert.build();
        let pin: [u8; 32] = cert
            .digest(MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            handler(acceptor.accept(socket).unwrap());
        });
        (
            Peer {
                address,
                pin,
                secret: [0x42; 32],
            },
            handle,
        )
    }
    fn authenticate(stream: &mut SslStream<TcpStream>) -> bool {
        let mut header = vec![0; MAGIC.len() + 32];
        if stream.read_exact(&mut header).is_err() {
            return false;
        }
        header[..MAGIC.len()] == *MAGIC && header[MAGIC.len()..] == [0x42; 32]
    }
    fn ready(stream: &mut SslStream<TcpStream>) {
        stream.write_all(&[0, 0, 0, 1, 0x22, 0, 5]).unwrap();
        stream.write_all(b"Phone").unwrap();
    }

    #[test]
    fn rejects_publicly_readable_or_symlinked_profiles() {
        let directory =
            std::env::temp_dir().join(format!("passkey-wifi-profile-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("phone.conf");
        fs::write(
            &path,
            format!(
                "192.168.1.10:40719\npk1:{}:{}\n",
                "11".repeat(32),
                "42".repeat(32)
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_from(&directory).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        assert!(load_from(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn validates_local_endpoints_and_pairing_codes() {
        assert_eq!(endpoint("192.168.1.10").unwrap().port(), PORT);
        assert!(endpoint("[fd00::1]:40719").is_ok());
        for address in [
            "8.8.8.8",
            "example.com",
            "0.0.0.0",
            "192.168.1.1:0",
            "192.168.1.1\nextra",
        ] {
            assert!(endpoint(address).is_err(), "{address}");
        }
        let code = format!("pk1:{}:{}", "11".repeat(32), "42".repeat(32));
        let peer = Peer::parse("192.168.1.10", &code).unwrap();
        assert_eq!(Peer::decode(&peer.encode()).unwrap().secret, peer.secret);
        assert!(Peer::parse("192.168.1.10", "pk1:short:invalid").is_err());
        assert!(Peer::decode(&(peer.encode() + "extra\n")).is_err());
    }

    #[test]
    fn rejects_wrong_phone_before_sending_the_secret() {
        let (tx, rx) = mpsc::channel();
        let (mut peer, handle) = server(move |mut stream| {
            let mut byte = [0];
            let got = stream.read(&mut byte).unwrap_or(0);
            tx.send(got).unwrap();
        });
        peer.pin[0] ^= 1;
        assert_eq!(
            peer.connect().err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(4)).unwrap(), 0);
        handle.join().unwrap();
    }

    #[test]
    fn wrong_pairing_secret_never_creates_a_link() {
        let (mut peer, handle) = server(|mut stream| {
            assert!(!authenticate(&mut stream));
        });
        peer.secret[0] ^= 1;
        assert!(peer.connect().is_err());
        handle.join().unwrap();
    }

    #[test]
    fn sends_cancel_while_reader_waits_and_closes_cleanly() {
        let (peer, handle) = server(|mut stream| {
            assert!(authenticate(&mut stream));
            ready(&mut stream);
            let mut cancel = [0; 9];
            stream.read_exact(&mut cancel).unwrap();
            assert_eq!(cancel, [0, 0, 0, 5, 0x11, 0, 0, 0, 7]);
            stream.write_all(b"OK").unwrap();
        });
        let (mut writer, label) = peer.connect().unwrap();
        assert_eq!(label, "Phone (Wi-Fi)");
        let mut reader = writer.clone();
        let (tx, rx) = mpsc::channel();
        let reading = thread::spawn(move || {
            let mut response = [0; 2];
            reader.read_exact(&mut response).unwrap();
            tx.send(response).unwrap();
        });
        writer.write_all(&[0, 0, 0, 5, 0x11, 0, 0, 0, 7]).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), *b"OK");
        writer.shutdown();
        reading.join().unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn rejects_overlong_phone_labels() {
        let (peer, handle) = server(|mut stream| {
            assert!(authenticate(&mut stream));
            stream.write_all(&[0, 0, 0, 1, 0x22, 1, 1]).unwrap();
        });
        assert!(peer.connect().is_err());
        handle.join().unwrap();
    }
}
