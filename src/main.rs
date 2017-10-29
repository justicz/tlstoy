#![allow(dead_code)]

use std::io::prelude::*;
use std::net::TcpStream;
use std::str;

extern crate rand;
use rand::{Rng, OsRng};

extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};

static LEGACY_RECORD_VERSION: u16 = 0x0301;
static LEGACY_PROTOCOL_VERSION: u16 = 0x0303;

enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    HelloRetryRequest = 6,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

enum ContentType {
    Invalid = 0,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
enum CipherSuite {
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
}

#[derive(Copy, Clone)]
enum CompressionMethod {
    CompressionMethodNULL = 0x00,
}

/*
 * Vector types
 */

struct SessionID {
    len: usize,
    data: Vec<u8>,
}

struct Extensions {
    len: usize,
    data: Vec<u8>,
}

struct CompressionMethods {
    len: usize,
    data: Vec<CompressionMethod>,
}

struct CipherSuites {
    len: usize,
    data: Vec<CipherSuite>,
}

/*
 * Message types
 */

struct ClientHello {
    /*  struct {
     *      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
     *      Random random;
     *      opaque legacy_session_id<0..32>;
     *      CipherSuite cipher_suites<2..2^16-2>;
     *      opaque legacy_compression_methods<1..2^8-1>;
     *      Extension extensions<8..2^16-1>;
     *  } ClientHello;
     */
    legacy_protocol_version: u16,
    random: [u8; 32],
    legacy_session_id: SessionID,
    cipher_suites: CipherSuites,
    legacy_compression_methods: CompressionMethods,
    extensions: Extensions,
}

struct Handshake {
    hs_type: HandshakeType,
    len: u32, // actually u24
    hello: ClientHello,
}

struct TLSPlaintext {
    content_type: ContentType,
    legacy_record_version: u16,
    len: u16,
    handshake: Handshake,
}


fn serialize_client_hello(client_hello: &ClientHello, out: &mut Vec<u8>) {
    /*
     * legacy_protocol_version
     */
    let _ = out.write_u16::<BigEndian>(client_hello.legacy_protocol_version);

    /*
     * random
     */
    out.extend_from_slice(&client_hello.random);

    /* 
     * legacy_session_id
     */
    let data = &client_hello.legacy_session_id.data;
    assert!(data.len() < 256);
    let _ = out.write_u8(data.len() as u8);
    out.extend_from_slice(data);

    /* 
     * cipher_suites
     */
    let data = &client_hello.cipher_suites.data;
    assert!((data.len()*2) < 65536);
    let _ = out.write_u16::<BigEndian>((data.len()*2) as u16);

    // Copy each cipher suite over
    for i in 0..data.len() {
        let _ = out.write_u16::<BigEndian>(data[i] as u16);
    }

    /*
     * legacy_compression_methods
     */
    let data = &client_hello.legacy_compression_methods.data;
    assert!(data.len() < 256);
    let _ = out.write_u8(data.len() as u8);

    // Copy each compression method over (noting that anything other than the
    // null compression method is nonstandard)
    for i in 0..data.len() {
        let _ = out.write_u8(data[i] as u8);
    }

    /*
     * extensions
     */
    let data = &client_hello.extensions.data;
    assert!(data.len() < 65536);
    let _ = out.write_u16::<BigEndian>(data.len() as u16);

    for i in 0..data.len() {
        let _ = out.write_u8(data[i] as u8);
    }
}

fn wrap_in_handshake(hs_type: HandshakeType, data: &Vec<u8>, out: &mut Vec<u8>) {
    let _ = out.write_u8(hs_type as u8);
    assert!(data.len() < 16777216);
    let _ = out.write_u24::<BigEndian>(data.len() as u32);
    out.extend_from_slice(data);
}

fn wrap_in_tls_plaintext(c_type: ContentType, data: &Vec<u8>, out: &mut Vec<u8>) {
    let _ = out.write_u8(c_type as u8);
    let _ = out.write_u16::<BigEndian>(LEGACY_RECORD_VERSION);
    assert!(data.len() < 65536);
    let _ = out.write_u16::<BigEndian>(data.len() as u16);
    out.extend_from_slice(data);
}

fn main() {
    let mut client_hello = ClientHello {
        legacy_protocol_version: LEGACY_PROTOCOL_VERSION,
        random: [1; 32],
        legacy_session_id: SessionID {
            len: 0,
            data: vec![],
        },
        cipher_suites: CipherSuites {
            len: 0,
            data: vec![CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA],
        },
        legacy_compression_methods: CompressionMethods {
            len: 0,
            data: vec![CompressionMethod::CompressionMethodNULL],
        },
        extensions: Extensions {
            len: 0,
            data: vec![],
        }
    };

    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut client_hello.random);

    let mut client_hello_serial = vec![];
    serialize_client_hello(&client_hello, &mut client_hello_serial);

    let mut handshake_serial = vec![];
    wrap_in_handshake(HandshakeType::ClientHello,
                      &client_hello_serial,
                      &mut handshake_serial);
    
    let mut plaintext_serial = vec![];
    wrap_in_tls_plaintext(ContentType::Handshake,
                          &handshake_serial,
                          &mut plaintext_serial);

    println!("{:?}", plaintext_serial);

    let mut stream = TcpStream::connect("tls.ctf.network:443").unwrap();

    let mut resp = [0; 32];

    let _ = stream.write(&plaintext_serial);
    let _ = stream.read(&mut resp);
    println!("{:?}", resp);
}

