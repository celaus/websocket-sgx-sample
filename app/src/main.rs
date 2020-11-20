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

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::os::unix::io::AsRawFd;
use std::net::ToSocketAddrs;
use std::net::SocketAddr;
use std::ffi::CString;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern {
    fn start_thread(eid: sgx_enclave_id_t, retval: *mut usize,
                            fd: c_int, hostname: *const c_char, cert: *const c_char) -> sgx_status_t;
    fn check(eid: sgx_enclave_id_t, retval: *mut usize,
                                fd: c_int, hostname: *const c_char, cert: *const c_char) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}


pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            println!("{:?}", x);
            return;
        },
    };

    let mut retval = sgx_status_t::SGX_SUCCESS;


    let cert = "./ca.cert";
    let hostname = "echo.websocket.org";
    let addr = lookup_ipv4(hostname, 443);
    let sock = std::net::TcpStream::connect(&addr).expect("[-] Connect tls server failed!");
    let mut tlsclient_id: usize = 0xFFFF_FFFF_FFFF_FFFF;
    let c_host = CString::new(hostname.to_string()).unwrap();
    let c_cert = CString::new(cert.to_string()).unwrap();

    let result = unsafe {
        start_thread(enclave.geteid(),
                    &mut tlsclient_id,
                    sock.as_raw_fd(),
                    c_host.as_ptr() as *const c_char,
                    c_cert.as_ptr() as *const c_char)
    };
    use std::thread;

    // wait to see if the thread is working
    thread::sleep(std::time::Duration::from_secs(10000));


    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    println!("[+] say_something success...");
    enclave.destroy();
}
