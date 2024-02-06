use std::{
    io::{Cursor, Seek},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tm_web_api::{Client, Server};
use tokio::{
    net::{TcpListener, UdpSocket},
    spawn,
};
use tokio_util::codec::LengthDelimitedCodec;

const HMAC_SHA256_KEY: [u8; 32] = [
    0xe7, 0x2a, 0x57, 0xb1, 0xd6, 0x19, 0xe4, 0x80, 0x84, 0x84, 0x6b, 0x25, 0x05, 0xa3, 0x2b, 0x77,
    0x48, 0x24, 0x97, 0x93, 0xec, 0xcc, 0xcb, 0x49, 0xbd, 0x0c, 0xb9, 0x59, 0xdd, 0xb4, 0x53, 0x31,
];

#[tokio::main]
async fn main() {
    let login = "jussy";
    let password = ")Tvr0Vb<uc{[<lKG";
    let port = 2350;
    let player_count_max = 32;
    let server_name = "jussy";

    let mut web_api_client = Client::new()
        .authenticate_with_server_account(login, password)
        .await
        .unwrap();

    let server = Server {
        title_id: "Trackmania".to_owned(),
        script_filename: "TM_TimeAttack_Online".to_owned(),
        port,
        player_count_max,
        player_count: 0,
        server_name: server_name.to_owned(),
        is_private: false,
        ip: "83.82.216.215".to_owned(),
        game_mode_custom_data: "".to_owned(),
        game_mode: "TimeAttack".to_owned(),
    };

    web_api_client.server_set(&server).await.unwrap();

    let socket_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    let tcp_listener = TcpListener::bind(socket_addr).await.unwrap();
    let udp_socket = UdpSocket::bind(socket_addr).await.unwrap();

    spawn(async move {
        loop {
            let mut buf = [0; 1024];
            let (len, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
            println!("{:?} bytes received from {:?}", len, addr);
        }
    });

    loop {
        let (tcp_stream, _addr) = tcp_listener.accept().await.unwrap();

        spawn(async move {
            let mut tcp_stream = LengthDelimitedCodec::builder()
                .little_endian()
                .new_framed(tcp_stream);

            let mut message = tcp_stream.next().await.unwrap().unwrap();
            verify_message_mac(&mut message);
            let mut message_reader = Cursor::new(message);
            let magic = message_reader.read_u16::<LittleEndian>().unwrap();
            assert_eq!(magic, 0x0380);
            message_reader.seek(std::io::SeekFrom::Current(32)).unwrap();
            let nine = message_reader.read_u32::<LittleEndian>().unwrap();
            assert_eq!(nine, 9);
            let message_type = message_reader.read_u8().unwrap();
            assert_eq!(message_type, 7);

            let mut message = tcp_stream.next().await.unwrap().unwrap();
            verify_message_mac(&mut message);
            let mut message_reader = Cursor::new(message);
            let magic = message_reader.read_u16::<LittleEndian>().unwrap();
            assert_eq!(magic, 0x0380);
            message_reader.seek(std::io::SeekFrom::Current(32)).unwrap();
            let nine = message_reader.read_u32::<LittleEndian>().unwrap();
            assert_eq!(nine, 9);
            let message_type = message_reader.read_u8().unwrap();
            assert_eq!(message_type, 6);
            let _time = message_reader.read_u32::<LittleEndian>().unwrap();
        });
    }
}

fn verify_message_mac(message: &mut [u8]) {
    let mut mac = [0; 32];
    mac.copy_from_slice(&message[2..34]);
    message[2..34].fill(0);

    let mut computed_mac = Hmac::<Sha256>::new_from_slice(&HMAC_SHA256_KEY).unwrap();
    computed_mac.update(message);
    computed_mac.verify(&mac.into()).unwrap();
}

fn compress_message(src: &[u8], _data: &[u8]) -> Vec<u8> {
    let dst_len = 1 + (src.len() + 254 - 15) / 255 + src.len();
    let mut dst = vec![0; dst_len];
    let mut dst_pos = 0;

    if src.len() >= 15 {
        dst[dst_pos] = 0xf0;
        dst_pos += 1;

        let mut rem = src.len() - 15;

        while rem >= 255 {
            dst[dst_pos] = 255;
            dst_pos += 1;
            rem -= 255;
        }

        dst[dst_pos] = rem as u8;
        dst_pos += 1;
    } else {
        dst[dst_pos] = (src.len() as u8) << 4;
        dst_pos += 1;
    }

    for &value in src {
        dst[dst_pos] = value;
        dst_pos += 1;
    }

    dst
}

fn decompress_message(src: &[u8], dst: &mut [u8], data: &[u8]) {
    let mut src_pos = 0;
    let mut dst_pos = 0;

    loop {
        let instruction = src[src_pos];
        src_pos += 1;

        let mut literal_length = (instruction >> 4) as usize;

        if literal_length == 15 {
            loop {
                let value = src[src_pos];
                src_pos += 1;

                literal_length += value as usize;

                if value != 255 {
                    break;
                }
            }
        }

        dst[dst_pos..dst_pos + literal_length]
            .copy_from_slice(&src[src_pos..src_pos + literal_length]);
        src_pos += literal_length;
        dst_pos += literal_length;

        if src_pos == src.len() {
            break;
        }

        let match_distance =
            u16::from_le_bytes(src[src_pos..src_pos + 2].try_into().unwrap()) as usize;
        src_pos += 2;

        let mut match_length = (instruction & 15) as usize;

        if match_length == 15 {
            loop {
                let value = src[src_pos];
                src_pos += 1;

                match_length += value as usize;

                if value != 255 {
                    break;
                }
            }
        }

        if match_distance > dst_pos {
            let data_match_pos = data.len() - (match_distance - dst_pos);

            dst[dst_pos..dst_pos + match_length]
                .copy_from_slice(&data[data_match_pos..data_match_pos + match_length]);
            dst_pos += match_length;
        } else {
            let mut match_pos = dst_pos - match_distance;

            for _ in 0..match_length {
                dst[dst_pos] = dst[match_pos];
                match_pos += 1;
                dst_pos += 1;
            }
        }
    }
}
