pub mod body;
pub mod message_socket;
pub mod client;
pub mod parser_utilities;
pub mod rtsp_machine;

pub(self) const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const LOG_RTSP: &str = "info_rtsp";
#[cfg(test)]
mod log_test;
#[cfg(test)]
use crate::{error_t as error, info_t as info, warn_t as warn}; // Workaround to use prinltn! for logs.
#[cfg(not(test))]
#[allow(unused_imports)]
use log::{error, info, warn};
pub use rtsp_types::Version;

use rtsp_machine::{Response, Request, Message};
fn log_rtsp_response(response: &Response) {
    let mut buffer = Vec::<u8>::new();
    response.write(&mut buffer).unwrap();
    info!(
        target: crate::LOG_RTSP,
        "S -> C: {}",
        String::from_utf8_lossy(buffer.as_slice())
    );
}

fn log_rtsp_request(request: &Request) {
    let mut buffer = Vec::<u8>::new();
    request.write(&mut buffer).unwrap();
    info!(
        target: crate::LOG_RTSP,
        "C -> S: {}",
        String::from_utf8_lossy(buffer.as_slice())
    );
}

fn log_rtsp_message(message: &Message) {
    match message {
        Message::Request(request) => log_rtsp_request(request),
        Message::Response(response) => log_rtsp_response(response),
        Message::Data(_) => {}
    }
}