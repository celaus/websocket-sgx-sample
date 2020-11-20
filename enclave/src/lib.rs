// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..


#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]


#[macro_use]
extern crate lazy_static;
extern crate sgx_types;
extern crate mio;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std; // STD
extern crate embedded_websocket;
extern crate anyhow;
extern crate rustls;
extern crate webpki;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
//use std::net::TcpStream;

use mio::net::TcpStream;
use embedded_websocket as ws;
use ws::{WebSocketCloseStatusCode, WebSocketReceiveMessageType, WebSocketOptions, WebSocketSendMessageType};
use std::thread;
use std::ffi::CStr;
use std::ptr;
use std::io::Read;
use rustls::Session;
use std::sync::{Arc, SgxMutex};

mod tlsclient;

use tlsclient::TlsClient;

lazy_static! {
    // TODO: Try declaring the channel receiver here to avoid any delay in broadcasting
    pub static ref PRICES: SgxMutex<Vec<(Vec<u8>, [u8; 65])>> = SgxMutex::new(Vec::new());
}

pub enum ConnectionState {
    Connecting,
    Data,
    PingPong,
    Closing
}


/// Build a `ClientConfig` from our arguments
fn make_config(cert: &str) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::new();

    let certfile = std::fs::File::open(cert).expect("Cannot open CA file");
    let mut reader = std::io::BufReader::new(certfile);
    //config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.root_store
        .add_pem_file(&mut reader).unwrap();
        //.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);


    Arc::new(config)
}


#[no_mangle]
pub extern "C" fn start_thread(fd: c_int, hostname: *const c_char, cert: *const c_char) -> sgx_status_t {
    let std_stream = std::net::TcpStream::new(fd).unwrap();
    let name_cast = unsafe { CStr::from_ptr(hostname).to_str() };
    let name = name_cast.unwrap();
    let hostname_ref = webpki::DNSNameRef::try_from_ascii_str(name).unwrap();

    let cert_cast = unsafe { CStr::from_ptr(cert).to_str() };
    let cert = cert_cast.unwrap();
    let cfg = make_config(cert);

    let address = name;
    println!("Connecting to: {} ({})", address, name);
    let mut socket = TcpStream::from_stream(std_stream).unwrap();    

    let mut stream = TlsClient::new(socket, hostname_ref, cfg.clone());
    
    let mut buffer1: [u8; 4000] = [0; 4000];
    let mut buffer2: [u8; 4000] = [0; 4000];
    let mut ws_client = ws::WebSocketClient::new_client(ws::EmptyRng::new());
    
    // initiate a websocket opening handshake
    let websocket_options = WebSocketOptions {
        path: "/",
        host: address,
        origin: "",
        sub_protocols: None,
        additional_headers: None,
    };
    
    let mut state = ConnectionState::Connecting;

    let (len, web_socket_key) = ws_client.client_connect(&websocket_options, &mut buffer1).unwrap();

    println!("Sending opening handshake: {} bytes", len);
    stream.write_all(&buffer1[..len]).unwrap();
    let s =  std::str::from_utf8(&buffer1[..len]).unwrap();
    println!("-> {}", s);
    // read the response from the server and check it to complete the opening handshake
    
    let t = thread::spawn(move || {

        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(32);
        stream.register(&mut poll);
    
        loop {
            poll.poll(&mut events, None).unwrap();
            for ev in events.iter() {
                if let Some(is_readable) = stream.ready(&mut poll, &ev) {
                    state = match state {
                        ConnectionState::Connecting if is_readable => {
                            println!("Connecting::READ");
                            let received_size = stream.read(&mut buffer1).unwrap();
                            let s =  std::str::from_utf8(&buffer1[..received_size]).unwrap();
                            println!("{}b <- {}",received_size,  s);
                            
                            if received_size == 0 {
                                continue;
                            }
                            ws_client.client_accept(&web_socket_key, &mut buffer1[..received_size]).unwrap();
                            println!("Opening handshake completed successfully");
                            ConnectionState::Data
                        }, 
                        ConnectionState::Data if is_readable => {
                            println!("Data::READ");
                            let received_size = stream.read(&mut buffer1).unwrap();
                            let s =  std::str::from_utf8(&buffer1[..received_size]).unwrap();
                            println!("{}b <- {}", received_size, s);
                                                        
                            if received_size == 0 {
                                continue;
                            }
                            let ws_result = ws_client.read(&buffer1[..received_size], &mut buffer2).unwrap();

                            match ws_result.message_type {
                                WebSocketReceiveMessageType::Text => {
                                    let s = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
                                    println!("Text reply from server: {}", s);
                                }
                                _ => {
                                    let s = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
                                    println!(
                                        "Unexpected response from server: {:?} {} bytes: {}",
                                        ws_result.message_type, ws_result.len_to, s
                                    );
                                }
                            }
                            let message = "Hello, World!";
                            let send_size = ws_client.write(
                                WebSocketSendMessageType::Text,
                                true,
                                &message.as_bytes(),
                                &mut buffer1,
                            ).unwrap();
                            stream.write_all(&buffer1[..send_size]).unwrap();
                            ConnectionState::Data
                        },
                        _ => {
                            println!("OTHER");
                            ConnectionState::Data
                        }
                    }
                }
            }
        }
    });
    sgx_status_t::SGX_SUCCESS
}

