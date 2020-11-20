

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use embedded_websocket as ws;
use ws::{WebSocketCloseStatusCode, WebSocketReceiveMessageType, WebSocketOptions, WebSocketSendMessageType};
use std::thread;
use std::ffi::CStr;
use std::ptr;
use std::io::Read;
use rustls::Session;
use std::sync::{Arc, SgxMutex};

extern crate mio;
use mio::net::TcpStream;

//#[macro_use]
//extern crate log;

const CLIENT: mio::Token = mio::Token(0);


/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
pub struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_session: rustls::ClientSession,
}

impl TlsClient {
    pub fn ready(&mut self,
             poll: &mut mio::Poll,
             ev: &mio::event::Event) -> Option<bool> {
        assert_eq!(ev.token(), CLIENT);
        
        let mut interest = Some(false);
        if ev.readiness().is_readable() {
            println!("# TLSClient Read interest");
            self.do_read();
            interest = Some(true);
        }

        if ev.readiness().is_writable() {
            println!("# TLSClient write interest");
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            return None;
        }

        self.reregister(poll);
        interest
    }
}

/// We implement `io::Write` and pass through to the TLS session
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_session.read(bytes)
    }
}

impl TlsClient {
    pub fn new(sock: TcpStream, hostname: webpki::DNSNameRef, cfg: Arc<rustls::ClientConfig>) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_session: rustls::ClientSession::new(&cfg, hostname),
        }
    }

    /// We're ready to do a read.
    pub fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            println!("TLS read error: {:?}", rc);
            self.closing = true;
            return;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            self.closing = true;
            self.clean_closure = true;
            return;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            self.closing = true;
            return;
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        let mut plaintext = Vec::new();
        let rc = self.tls_session.read_to_end(&mut plaintext);
        if !plaintext.is_empty() {
            io::stdout().write_all(&plaintext).unwrap();
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if rc.is_err() {
            let err = rc.unwrap_err();
            println!("Plaintext read error: {:?}", err);
            self.clean_closure = err.kind() == io::ErrorKind::ConnectionAborted;
            self.closing = true;
            return;
        }
    }

    pub fn do_write(&mut self) {
        self.tls_session.write_tls(&mut self.socket).unwrap();
    }

    pub fn register(&self, poll: &mut mio::Poll) {
        poll.register(&self.socket,
                      CLIENT,
                      self.ready_interest(),
                      mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
    }

    pub fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(&self.socket,
                        CLIENT,
                        self.ready_interest(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
    }

    // Use wants_read/wants_write to register for different mio-level
    // IO readiness events.
    pub fn ready_interest(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closing
    }
}
