mod compression;

use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use anyhow::{bail, Result};
use futures_util::{SinkExt, TryStreamExt};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tm_web_api::{DedicatedServerClient, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::LengthDelimitedCodec,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let ip_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let port = 2351;
    let socket_addr = SocketAddr::new(ip_addr, port);

    let tcp_listener = TcpListener::bind(socket_addr).await?;

    let mut client = DedicatedServerClient::new("JussyDr", "]3{d</}Q2M1cSlT%");

    let account_id = "30db4490-8533-4b00-9597-d64ee5da8036";

    let server_config = ServerConfig {
        title_id: "Trackmania",
        script_file_name: "TM_TimeAttack_Online",
        port,
        player_count_max: 32,
        player_count: 1,
        server_name: "JussyDr",
        is_private: false,
        ip: "83.82.216.215",
        game_mode_custom_data: "",
        game_mode: "TimeAttack",
    };

    client
        .register_dedicated_server(account_id, &server_config)
        .await?;

    tracing::info!("started");

    loop {
        let (tcp_stream, _socket_addr) = tcp_listener.accept().await?;

        tokio::spawn(handle_connection(tcp_stream));
    }
}

async fn handle_connection(tcp_stream: TcpStream) -> Result<()> {
    tracing::info!("connection");

    let mut tcp_stream = LengthDelimitedCodec::builder()
        .little_endian()
        .new_framed(tcp_stream);

    let frame = tcp_stream.try_next().await?.unwrap();
    let payload = parse_frame(frame)?;
    parse_message(payload)?;

    let frame = tcp_stream.try_next().await?.unwrap();
    let payload = parse_frame(frame)?;
    parse_message(payload)?;

    let frame = vec![];
    tcp_stream.send(frame.into()).await?;

    let frame = vec![];
    tcp_stream.send(frame.into()).await?;

    while let Some(_frame) = tcp_stream.try_next().await? {}

    tracing::info!("disconnection");

    Ok(())
}

const HS256_KEY: [u8; 32] = [
    0xe7, 0x2a, 0x57, 0xb1, 0xd6, 0x19, 0xe4, 0x80, 0x84, 0x84, 0x6b, 0x25, 0x05, 0xa3, 0x2b, 0x77,
    0x48, 0x24, 0x97, 0x93, 0xec, 0xcc, 0xcb, 0x49, 0xbd, 0x0c, 0xb9, 0x59, 0xdd, 0xb4, 0x53, 0x31,
];

fn parse_frame(mut frame: BytesMut) -> Result<BytesMut> {
    // TODO: frame length checking while parsing.

    let signature = u16::from_le_bytes(frame[..2].try_into().unwrap());

    if signature != 0x0380 {
        bail!("invalid frame signature")
    }

    let mut mac = [0; 32];
    mac.copy_from_slice(&frame[2..34]);

    let mut hs256 = Hmac::<Sha256>::new_from_slice(&HS256_KEY).unwrap();
    frame[2..34].fill(0);
    hs256.update(&frame);
    hs256.verify(&mac.into())?;

    Ok(frame.split_off(34))
}

fn parse_message(message: BytesMut) -> Result<()> {
    let mut reader = message.reader();

    if read_u32(&mut reader)? != 9 {
        bail!("invalid version");
    }

    match read_u8(&mut reader)? {
        7 => {}
        6 => {
            let _time = read_u32(&mut reader)?;
        }
        _ => bail!("unknown message type"),
    }

    Ok(())
}

fn read_u8(mut reader: impl Read) -> Result<u8> {
    let mut bytes = [0; size_of::<u8>()];
    reader.read_exact(&mut bytes)?;

    Ok(u8::from_le_bytes(bytes))
}

fn read_u32(mut reader: impl Read) -> Result<u32> {
    let mut bytes = [0; size_of::<u32>()];
    reader.read_exact(&mut bytes)?;

    Ok(u32::from_le_bytes(bytes))
}
