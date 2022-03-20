use clap::{App, Arg};
use futures::lock::Mutex;
use log::{info};
use rrtsp_client::client::{Body, Client, Data, Host, Url, Version};
use std::sync::Arc;

// Usage example: cargo run --example simple_client -- --url rtsp://admin:12345@192.168.1.178:10554/tcp/av0_0

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let matches = App::new("RRTSP client example")
        .version("0.1.0")
        .author("Lattice0")
        .about("Loads data from RTSP server")
        .arg(
            Arg::with_name("url")
                .short("url")
                .long("url")
                .takes_value(true)
                .required(true)
                .help("URL of rtsp server"),
        )
        .get_matches();
    let uri_str = matches.value_of("url").expect("missing url");
    let url = Url::parse(uri_str).unwrap();
    let port = url.port().unwrap_or(554);

    let ip_address = match url.host() {
        //For RTSP URLs, URL.host() does not return Host::Ipv4 or 6, it returns Domain
        Some(Host::Domain(domain)) => format!("{}:{}", domain, port).parse().unwrap(),
        None => panic!("missing host/url"),
        _ => panic!("only IP hosts are accepted. Your host: {:?}", url.host()),
    };
    info!("Starting RTSP client for uri {}", uri_str);
    let rtsp_client = Arc::new(Mutex::new(
        Client::new(uri_str, None, None, Version::V1_0).unwrap(),
    ));
    Client::play(
        rtsp_client,
        ip_address,
        Arc::new(|data: &Data<Body>| {
            info!("<<< {} bytes", &data.len());
        }),
    )
    .await
    .unwrap();
    Ok(())
}
