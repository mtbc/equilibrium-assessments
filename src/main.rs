use base64::{engine::general_purpose, Engine};
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Arg, Command, ValueHint};
use futures::{stream::FuturesUnordered, StreamExt};
use ip_rfc::global;
use k256::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    elliptic_curve,
    schnorr::signature::{
        self,
        hazmat::{PrehashSigner, PrehashVerifier},
    },
    PublicKey, SecretKey,
};
use local_ip_address::local_ip;
use openssl::{
    sha::sha512,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion},
};
use std::{collections::HashMap, pin::Pin};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    runtime::Handle,
    task::JoinError,
};
use tokio_openssl::SslStream;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate version;

// TokenType::NodePublic from Ripple
const NODE_PUBLIC_TYPE: u8 = 28;

const READ_BUFFER_SIZE: usize = 1024;

const DEFAULT_PEERS: &[&str] = &[
    // Ripple Labs
    "r.ripple.com:51235",
    // Alloy Networks
    "zaphod.alloy.ee:51235",
];

lazy_static! {
    static ref EPOCH: DateTime<Utc> = DateTime::<Utc>::from_utc(
        NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
        Utc
    );
    static ref USER_AGENT: String = format!("mtbc-eiger-{}", version!());
}

#[derive(Debug, Error)]
enum Error {
    #[error("bad peer key")]
    BadPeerKey { message: String },
    #[error("cannot decode base-58")]
    Base58(#[from] bs58::decode::Error),
    #[error("cannot decode base-64")]
    Base64(#[from] base64::DecodeError),
    #[error("peer connection aborted")]
    ConnectionAborted(#[from] JoinError),
    #[error("HTTP upgrade failure")]
    HttpUpgrade { response: String },
    #[error("I/O failure")]
    Io(#[from] std::io::Error),
    #[error("missing header")]
    MissingHeader { name: String },
    #[error("cannot decode node key")]
    NodeKey(#[from] elliptic_curve::Error),
    #[error("SSL failure")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("cannot read from peer")]
    PeerMessage { message: String },
    #[error("cannot sign digest")]
    SignDigest(#[from] signature::Error),
    #[error("SSL failure")]
    Ssl(#[from] openssl::ssl::Error),
}

// Command-line argument values.
#[derive(Clone, Debug)]
struct Settings {
    key_file: String,
    peers: Vec<String>,
}

impl Settings {
    fn new() -> Self {
        let cli = Command::new("p2p-handshake")
            .arg(
                Arg::new("key")
                    .short('k')
                    .long("key")
                    .value_hint(ValueHint::FilePath)
                    .default_value("key-sec1.pem")
                    .env("RIPPLE_KEY_FILE")
                    .help("filename of PEM-encoded SEC1 EC private key"),
            )
            .arg(
                Arg::new("peers")
                    .short('p')
                    .long("peers")
                    .num_args(1..)
                    .default_values(DEFAULT_PEERS)
                    .env("RIPPLE_PEERS")
                    .help("network addresses for peer nodes"),
            );
        let matches = cli.get_matches();
        let key_file = matches.get_one::<String>("key").unwrap();
        let peers = matches.get_many::<String>("peers").unwrap();
        Settings {
            key_file: key_file.clone(),
            peers: Vec::from_iter(peers.map(Clone::clone)),
        }
    }
}

// This node's Secp256k1 key.
#[derive(Clone, Debug)]
struct NodeKey {
    // the base-58 public key ready for sharing
    public_ripple: String,
    // the signing key for generating verifiable signatures
    signing: SigningKey,
}

impl NodeKey {
    fn from_sec1_pem(encoded_key: String) -> Result<Self, Error> {
        let secret = SecretKey::from_sec1_pem(encoded_key.trim())?;
        let public = secret.public_key();
        Ok(NodeKey {
            public_ripple: Self::encode_node_public_key(&public),
            signing: secret.into(),
        })
    }

    fn encode_node_public_key(public_key: &PublicKey) -> String {
        let mut public_key_bytes = public_key.to_sec1_bytes().to_vec();
        public_key_bytes.insert(0, NODE_PUBLIC_TYPE);

        bs58::encode(public_key_bytes)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .with_check()
            .into_string()
    }

    fn sign_hash(&self, hash: &[u8]) -> Result<Signature, signature::Error> {
        self.signing.sign_prehash(hash)
    }
}

fn decode_node_public_key(public_key: &str) -> Result<PublicKey, Error> {
    let public_key_bytes: Vec<u8> = bs58::decode(public_key)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(None)
        .into_vec()?;

    if public_key_bytes.is_empty() || public_key_bytes[0] != NODE_PUBLIC_TYPE {
        Err(Error::BadPeerKey {
            message: "expected public key type".to_string(),
        })
    } else {
        Ok(PublicKey::from_sec1_bytes(&public_key_bytes[1..])?)
    }
}

// Format header lines for sending over HTTP.
#[derive(Clone, Debug, Default)]
struct Headers(HashMap<String, String>);

impl Headers {
    fn add(&mut self, name: impl ToString, value: impl ToString) {
        self.0.insert(name.to_string(), value.to_string());
    }

    fn concatenate(&self, eol: impl ToString) -> String {
        let eol = &eol.to_string();
        self.0
            .iter()
            .fold(Default::default(), |s, (n, v)| s + n + ": " + v + eol)
    }
}

// Shake hands with configured peers.
#[tokio::main]
async fn main() -> Result<(), Error> {
    let settings = Settings::new();

    // set up this node's cryptographic key

    let key_sec1_pem = std::fs::read_to_string(settings.key_file)?;
    let node_key = NodeKey::from_sec1_pem(key_sec1_pem)?;

    // prepare TLS configuration

    let mut ssl_context = SslContextBuilder::new(SslMethod::tls_client())?;
    ssl_context.set_default_verify_paths()?;
    ssl_context.set_cipher_list(
        "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK",
    )?;
    ssl_context.set_min_proto_version(Some(SslVersion::TLS1_1))?;
    let ssl_context = ssl_context.build();

    // set up peer connections

    let mut handshake_futures = Vec::new();

    for peer in settings.peers {
        let (ssl_context, node_key) = (ssl_context.clone(), node_key.clone());
        handshake_futures.push(async move {
            (
                peer.clone(),
                do_handshake(ssl_context, node_key, peer).await,
            )
        });
    }

    // spawn handshakes with peers

    let handle = Handle::current();
    let mut completions = handshake_futures
        .into_iter()
        .map(|f| handle.spawn(f))
        .collect::<FuturesUnordered<_>>();

    // collect and report outcomes of peer handshakes

    handle
        .spawn_blocking(|| async move {
            while let Some(completion) = completions.next().await {
                let (peer, message_types) = completion?;
                println!("peer {peer} sent message types: {:?}", message_types?);
            }
            Ok(())
        })
        .await?
        .await
}

// Shake hands with one given peer.
async fn do_handshake(
    ssl_context: SslContext,
    node_key: NodeKey,
    peer: String,
) -> Result<Vec<u16>, Error> {
    // make TLS connection to peer

    let stream = TcpStream::connect(peer.clone()).await?;
    let ssl = Ssl::new(ssl_context.as_ref())?;
    let mut stream = SslStream::new(ssl, stream)?;
    Pin::new(&mut stream).connect().await?;
    let mut buffer = vec![0; READ_BUFFER_SIZE];

    // compute session signature, cf. makeSharedValue in Ripple's Handshake.cpp

    let count = stream.ssl().finished(&mut buffer);
    let local_finished_digest = sha512(&buffer[0..count]);

    let count = stream.ssl().peer_finished(&mut buffer);
    let peer_finished_digest = sha512(&buffer[0..count]);

    let fingerprint = local_finished_digest
        .iter()
        .zip(peer_finished_digest.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let fingerprint_digest: &[u8] = &sha512(&fingerprint);
    let signed: Signature = node_key.sign_hash(&fingerprint_digest[0..32])?;

    // prepare peering request

    let mut headers = Headers::default();
    headers.add("User-Agent", USER_AGENT.clone());
    headers.add("Connection", "Upgrade");
    headers.add("Upgrade", "XRPL/2.2");
    headers.add("Connect-As", "Peer");
    headers.add(
        "Network-Time",
        Utc::now().signed_duration_since(*EPOCH).num_seconds(),
    );
    headers.add("Public-Key", node_key.public_ripple.clone());
    headers.add(
        "Session-Signature",
        general_purpose::STANDARD.encode(signed.to_der().as_bytes()),
    );
    if let Ok(ip) = local_ip() {
        if global(&ip) {
            headers.add("Local-IP", ip);
        }
    }

    // request XRP Ledger connection

    stream
        .write_all(format!("GET / HTTP/1.1\r\n{}\r\n", headers.concatenate("\r\n")).as_bytes())
        .await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut upgrade_response = String::new();
    reader.read_line(&mut upgrade_response).await?;
    if !upgrade_response.starts_with("HTTP/1.1 101 ") {
        return Err(Error::HttpUpgrade {
            response: upgrade_response,
        });
    }

    // granted upgrade, now get response headers

    let count = reader.read(&mut buffer).await?;
    let mut headers = HashMap::new();
    let lines = String::from_utf8_lossy(&buffer[0..count]);
    for line in lines.split_terminator("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            let (name, value) = (name.trim().to_lowercase(), value.trim());
            if !(name.is_empty() || value.is_empty()) {
                headers.insert(name, value);
            }
        }
    }

    // verify peer's session signature

    let peer_key = headers.get("public-key").ok_or(Error::MissingHeader {
        name: "Public-Key".to_string(),
    })?;
    let peer_key = decode_node_public_key(peer_key)?;
    let verifying_key: VerifyingKey = peer_key.into();
    let session_signature = headers
        .get("session-signature")
        .ok_or(Error::MissingHeader {
            name: "Session-Signature".to_string(),
        })?;
    let signed = Signature::from_der(&general_purpose::STANDARD.decode(session_signature)?)?;
    verifying_key.verify_prehash(&fingerprint_digest[0..32], &signed)?;

    // get first few protocol messages to demonstrate successful handshake

    let mut message_types = Vec::with_capacity(5);
    for _ in 0..message_types.capacity() {
        if let Ok(count) = reader.read(&mut buffer).await {
            if count < 6 {
                return Err(Error::PeerMessage {
                    message: "missing header".to_string(),
                });
            }

            // got the start of a message so decode header and note type

            let payload_size = BigEndian::read_u32(&buffer[0..4]) as usize;
            let message_type = BigEndian::read_u16(&buffer[4..6]);
            message_types.push(message_type);

            // consume remainder of current message

            let mut remaining_bytes = payload_size + 6 - count;
            while remaining_bytes > 0 {
                if let Ok(count) = reader.read(&mut buffer).await {
                    if count <= remaining_bytes {
                        remaining_bytes -= count;
                    } else {
                        return Err(Error::PeerMessage {
                            message: "cannot handle combined messages".to_string(),
                        });
                    }
                } else {
                    return Err(Error::PeerMessage {
                        message: "nothing to read".to_string(),
                    });
                }
            }
        } else {
            return Err(Error::PeerMessage {
                message: "nothing to read".to_string(),
            });
        }
    }

    // close connection with peer

    let mut stream = reader.into_inner();
    stream.shutdown().await?;

    Ok(message_types)
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    #[test]
    fn headers() {
        const TERMINATOR: char = '|';

        let mut headers = crate::Headers::default();
        for (name, value) in [("One", "Foo"), ("Two", "Bar"), ("Three", "Baz")] {
            headers.add(name, value);
        }
        let headers = headers.concatenate(TERMINATOR);

        let mut headers = headers.split_terminator(TERMINATOR).collect::<HashSet<_>>();
        for header in ["One: Foo", "Two: Bar", "Three: Baz"] {
            assert!(headers.remove(header));
        }
        assert!(headers.is_empty());
    }
}
