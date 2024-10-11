mod compression;

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use anyhow::{bail, Result};
use compression::{compress, decompress};
use futures_util::{SinkExt, TryStreamExt};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tm_web_api::{DedicatedServerClient, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::LengthDelimitedCodec,
};

pub async fn run() -> Result<()> {
    let ip_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let port = 2351;
    let socket_addr = SocketAddr::new(ip_addr, port);

    let tcp_listener = TcpListener::bind(socket_addr).await?;

    let mut client = DedicatedServerClient::new("JussyDr", "JussyDr", "]3{d</}Q2M1cSlT%");

    let account_id = client.get_account_id().await?.to_owned();

    let client_config = client.get_client_config().await?;

    let server_config = ServerConfig {
        title_id: "Trackmania",
        script_file_name: "TM_TimeAttack_Online",
        port,
        player_count_max: 32,
        player_count: 1,
        server_name: "JussyDr",
        is_private: false,
        ip: &client_config.settings.client_ip,
        game_mode_custom_data: "",
        game_mode: "TimeAttack",
    };

    client
        .register_dedicated_server(&account_id, &server_config)
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
    let request_time_ms = parse_message(payload)?.unwrap();

    let payload = create_advertisement_message(request_time_ms)?;
    let frame = create_frame(&payload);
    tcp_stream.send(frame.into()).await?;

    // second frame only sent if num_maps >= 22
    // let frame = create_frame(&[]);
    // tcp_stream.send(frame.into()).await?;

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

fn parse_message(message: BytesMut) -> Result<Option<u32>> {
    let mut reader = message.reader();

    if read_u32(&mut reader)? != 9 {
        bail!("invalid version");
    }

    let message = match read_u8(&mut reader)? {
        7 => None,
        6 => {
            let time_ms = read_u32(&mut reader)?;

            Some(time_ms)
        }
        _ => bail!("unknown message type"),
    };

    Ok(message)
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

fn create_frame(data: &[u8]) -> Vec<u8> {
    let signature: u16 = 0x0381;
    let uncompressed_len = data.len() as u32;
    let compressed = compress(data);

    let mut frame = vec![];
    frame.extend_from_slice(&signature.to_le_bytes());
    frame.extend_from_slice(&[0; 32]);
    frame.extend_from_slice(&uncompressed_len.to_le_bytes());
    frame.extend_from_slice(&compressed);

    let mut hs256 = Hmac::<Sha256>::new_from_slice(&HS256_KEY).unwrap();
    hs256.update(&frame);
    let mac = hs256.finalize();

    frame[2..2 + 32].copy_from_slice(&mac.into_bytes());

    frame
}

fn create_advertisement_message(request_message_time_ms: u32) -> Result<Vec<u8>> {
    let id = "MNtEkIUzSwCVl9ZO5dqANg";
    let game = "Trackmania";
    let srv = "#SRV#";
    let max_num_spectators = 32;
    let max_num_players = 32;
    let num_current_players = 1;
    let name = "Test";
    let world = "World";
    let comment = "";
    let game_date = "2024-06-14_20_00";
    let game_build = "1.1.0+2023-10-09";
    let script_desc = "$zIn $<$t$6F9Time Attack$> mode, the goal is to set the $<$t$6F9best time$>.\n\nYou have as many tries as you want, and you can $<$t$6F9retry$> when you want by pressing the respawn button.\n\nWhen the time is up, the $<$t$6F9winner$> is the player with the $<$t$6F9best time$>.";
    let script_info = "TYPE: Free for all\nOBJECTIVE: Set the best time on the track.";
    let script = "Trackmania/TM_TimeAttack_Online.Script.txt";

    let mut data = vec![];
    data.extend_from_slice(&[0x50, 0xd7, 0xd8, 0x52, 0x53, 0x2f, 0x09]); // always the same
    write_string(&mut data, id)?;
    write_string(&mut data, game)?;
    write_string(&mut data, srv)?;
    data.push(num_current_players);
    data.push(max_num_players);
    data.push(0);
    data.push(max_num_spectators);
    write_string(&mut data, name)?;
    data.extend_from_slice(&[0; 20]);
    write_u32(&mut data, 24)?; // something with hide_server
    write_u32(&mut data, 0)?;
    write_string(&mut data, world)?;
    write_string(&mut data, comment)?;
    write_string(&mut data, game_date)?;
    write_string(&mut data, game_build)?;
    write_formatted_string(&mut data, script_desc)?;
    write_formatted_string(&mut data, script_info)?;
    write_u32(&mut data, 3)?;
    data.extend_from_slice(&[0; 6]);
    write_u32(&mut data, 8)?;
    write_u32(&mut data, 10000)?;
    write_u32(&mut data, 1)?;
    write_string(&mut data, script)?;
    data.extend_from_slice(&[1]); // total num maps (can be greater than 25)
    write_u32(&mut data, 1)?; // num maps to display, capped at 25:
    write_string(&mut data, "Summer 2021 - 21")?; // map name
    data.extend_from_slice(&[0x78, 0xe6, 0x00, 0x00, 0x00, 0x23, 0x00]); // G G G G C C ? where G = gold time, C = display cost (these bytes only depend on map, check earlier api calls)
    write_u32(&mut data, 1)?;
    write_u32(&mut data, 3)?;
    write_u32(&mut data, 26)?;
    data.extend_from_slice(&[0x01]);
    write_string(&mut data, "B9bNWCov2ZG7EWNBxYc7kJQQrXg")?; // map id

    std::fs::write("actual", &data).unwrap();

    let mut message = vec![];
    write_u32(&mut message, 9)?;
    message.extend_from_slice(&[5]); // message type?
    write_u32(&mut message, request_message_time_ms)?;
    write_u32(&mut message, data.len() as u32)?; // length of data
    message.extend_from_slice(&data);

    Ok(message)
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes)?;

    Ok(())
}

fn write_u32(writer: &mut impl Write, value: u32) -> Result<()> {
    write_bytes(writer, &value.to_le_bytes())?;

    Ok(())
}

fn write_string(writer: &mut impl Write, s: &str) -> Result<()> {
    write_u32(writer, s.len() as u32)?;
    write_bytes(writer, s.as_bytes())?;

    Ok(())
}

fn write_formatted_string(writer: &mut impl Write, s: &str) -> Result<()> {
    let utf8_bom = [0xef, 0xbb, 0xbf];
    let utf8_private_use_2 = [0xc2, 0x92];

    let len = utf8_bom.len() + utf8_private_use_2.len() + s.len();

    write_u32(writer, len as u32)?;
    write_bytes(writer, &utf8_bom)?;
    write_bytes(writer, &utf8_private_use_2)?;
    write_bytes(writer, s.as_bytes())?;

    Ok(())
}
