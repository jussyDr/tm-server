use std::{
    io::{Cursor, Read},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::{SinkExt, StreamExt};
use tm_web_api::{Client, Server};
use tokio::{
    net::{TcpListener, UdpSocket},
    spawn,
};
use tokio_util::codec::LengthDelimitedCodec;

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

            let message = tcp_stream.next().await.unwrap().unwrap();

            let mut message_decoder = Cursor::new(message);
            let client_magic = message_decoder.read_u16::<LittleEndian>().unwrap();
            assert_eq!(client_magic, 0x0380);
            let mut checksum = [0; 32];
            message_decoder.read_exact(&mut checksum).unwrap();
            let nine = message_decoder.read_u32::<LittleEndian>().unwrap();
            assert_eq!(nine, 9);
            let message_type = message_decoder.read_u8().unwrap();
            assert_eq!(message_type, 7);

            let message = tcp_stream.next().await.unwrap().unwrap();
            let mut message_decoder = Cursor::new(message);
            let client_magic = message_decoder.read_u16::<LittleEndian>().unwrap();
            assert_eq!(client_magic, 0x0380);
            let mut checksum = [0; 32];
            message_decoder.read_exact(&mut checksum).unwrap();
            let nine = message_decoder.read_u32::<LittleEndian>().unwrap();
            assert_eq!(nine, 9);
            let message_type = message_decoder.read_u8().unwrap();
            assert_eq!(message_type, 6);
            let _time = message_decoder.read_u32::<LittleEndian>().unwrap();

            let x = vec![
                0x81, 0x03, 0xef, 0x09, 0xd0, 0xaf, 0x76, 0x62, 0x50, 0xe0, 0xd0, 0x82, 0x30, 0x4c,
                0x53, 0xc1, 0x56, 0xcf, 0x52, 0xb6, 0xda, 0xc3, 0xfc, 0xe4, 0x78, 0x33, 0xf2, 0xdd,
                0x02, 0x57, 0x5c, 0x46, 0x22, 0x61, 0x71, 0x03, 0x00, 0x00, 0xfe, 0x45, 0x09, 0x00,
                0x00, 0x00, 0x05, 0x98, 0x84, 0x5f, 0x00, 0x64, 0x03, 0x00, 0x00, 0x50, 0xd7, 0xd8,
                0x52, 0x53, 0x2f, 0x09, 0x16, 0x00, 0x00, 0x00, 0x66, 0x61, 0x56, 0x6a, 0x66, 0x6f,
                0x77, 0x4e, 0x51, 0x77, 0x57, 0x53, 0x70, 0x70, 0x59, 0x4b, 0x5f, 0x7a, 0x59, 0x53,
                0x51, 0x51, 0x0a, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x6d, 0x61, 0x6e,
                0x69, 0x61, 0x05, 0x00, 0x00, 0x00, 0x23, 0x53, 0x52, 0x56, 0x23, 0x01, 0x20, 0x00,
                0x20, 0x05, 0x00, 0x00, 0x00, 0x6a, 0x75, 0x73, 0x73, 0x79, 0x00, 0x00, 0x02, 0x00,
                0x13, 0x18, 0x13, 0x00, 0xf6, 0xab, 0x05, 0x00, 0x00, 0x00, 0x57, 0x6f, 0x72, 0x6c,
                0x64, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x32, 0x30, 0x32, 0x34, 0x2d,
                0x30, 0x31, 0x2d, 0x31, 0x30, 0x5f, 0x31, 0x32, 0x5f, 0x30, 0x30, 0x10, 0x00, 0x00,
                0x00, 0x31, 0x2e, 0x31, 0x2e, 0x30, 0x2b, 0x32, 0x30, 0x32, 0x33, 0x2d, 0x31, 0x30,
                0x2d, 0x30, 0x39, 0x17, 0x01, 0x00, 0x00, 0xef, 0xbb, 0xbf, 0xc2, 0x92, 0x24, 0x7a,
                0x49, 0x6e, 0x20, 0x24, 0x3c, 0x24, 0x74, 0x24, 0x36, 0x46, 0x39, 0x54, 0x69, 0x6d,
                0x65, 0x20, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x24, 0x3e, 0x20, 0x6d, 0x6f, 0x64,
                0x65, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x6f, 0x61, 0x6c, 0x20, 0x69, 0x73,
                0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x24, 0x3c,
                0x24, 0x74, 0x24, 0x36, 0x46, 0x39, 0x62, 0x65, 0x73, 0x74, 0x20, 0x74, 0x69, 0x6d,
                0x65, 0x24, 0x3e, 0x2e, 0x0a, 0x0a, 0x59, 0x6f, 0x75, 0x20, 0x68, 0x61, 0x76, 0x65,
                0x20, 0x61, 0x73, 0x20, 0x6d, 0x61, 0x6e, 0x79, 0x20, 0x74, 0x72, 0x69, 0x65, 0x73,
                0x20, 0x61, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x2c, 0x20,
                0x61, 0x6e, 0x64, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x79, 0x00, 0xc5, 0x72,
                0x65, 0x74, 0x72, 0x79, 0x24, 0x3e, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x2b, 0x00, 0xc1,
                0x20, 0x62, 0x79, 0x20, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x87, 0x00,
                0xf1, 0x06, 0x72, 0x65, 0x73, 0x70, 0x61, 0x77, 0x6e, 0x20, 0x62, 0x75, 0x74, 0x74,
                0x6f, 0x6e, 0x2e, 0x0a, 0x0a, 0x57, 0x68, 0x65, 0x6e, 0x1a, 0x00, 0xb1, 0x74, 0x69,
                0x6d, 0x65, 0x20, 0x69, 0x73, 0x20, 0x75, 0x70, 0x2c, 0x10, 0x00, 0x04, 0x9e, 0x00,
                0xb1, 0x77, 0x69, 0x6e, 0x6e, 0x65, 0x72, 0x24, 0x3e, 0x20, 0x69, 0x73, 0x18, 0x00,
                0xb1, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x20, 0x77, 0x69, 0x74, 0x68, 0x10, 0x00,
                0x04, 0x28, 0x00, 0x08, 0xc6, 0x00, 0x23, 0x42, 0x00, 0x1b, 0x01, 0xf3, 0x10, 0x54,
                0x59, 0x50, 0x45, 0x3a, 0x20, 0x46, 0x72, 0x65, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20,
                0x61, 0x6c, 0x6c, 0x0a, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x49, 0x56, 0x45, 0x3a,
                0x20, 0x53, 0x09, 0x01, 0x05, 0x3b, 0x00, 0x23, 0x20, 0x6f, 0x8c, 0x00, 0x63, 0x72,
                0x61, 0x63, 0x6b, 0x2e, 0x03, 0x9e, 0x01, 0xf9, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                0x00, 0x10, 0x27, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a, 0xec, 0x01, 0x82, 0x2f,
                0x54, 0x4d, 0x5f, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x01, 0x77, 0x5f, 0x4f, 0x6e, 0x6c,
                0x69, 0x6e, 0x65, 0xb7, 0x02, 0xfe, 0x0e, 0x05, 0x05, 0x00, 0x00, 0x00, 0x0e, 0x00,
                0x00, 0x00, 0x46, 0x61, 0x6c, 0x6c, 0x20, 0x32, 0x30, 0x32, 0x33, 0x20, 0x2d, 0x20,
                0x30, 0x31, 0x90, 0x65, 0x00, 0x00, 0xc7, 0x0f, 0x19, 0x00, 0x7e, 0x32, 0x60, 0x6d,
                0x00, 0x00, 0xd2, 0x0d, 0x19, 0x00, 0x6f, 0x33, 0x30, 0x75, 0x00, 0x00, 0x46, 0x19,
                0x00, 0x00, 0x7e, 0x34, 0x78, 0x69, 0x00, 0x00, 0x66, 0x0a, 0x32, 0x00, 0x71, 0x35,
                0x30, 0x75, 0x00, 0x00, 0x4f, 0x08, 0xb4, 0x00, 0xf0, 0x94, 0x03, 0x00, 0x00, 0x00,
                0x1a, 0x00, 0x00, 0x00, 0x01, 0x1b, 0x00, 0x00, 0x00, 0x43, 0x4d, 0x62, 0x55, 0x73,
                0x34, 0x4f, 0x7a, 0x63, 0x44, 0x45, 0x77, 0x55, 0x63, 0x55, 0x55, 0x66, 0x4f, 0x6f,
                0x6e, 0x55, 0x6b, 0x34, 0x62, 0x69, 0x74, 0x38, 0x1b, 0x00, 0x00, 0x00, 0x7a, 0x48,
                0x6b, 0x4c, 0x4e, 0x70, 0x61, 0x64, 0x43, 0x77, 0x67, 0x36, 0x6d, 0x38, 0x69, 0x4a,
                0x68, 0x70, 0x6d, 0x69, 0x5a, 0x32, 0x49, 0x42, 0x70, 0x70, 0x64, 0x1b, 0x00, 0x00,
                0x00, 0x4c, 0x34, 0x5a, 0x61, 0x51, 0x38, 0x47, 0x77, 0x4c, 0x6a, 0x4d, 0x52, 0x41,
                0x6e, 0x6d, 0x35, 0x78, 0x61, 0x66, 0x57, 0x62, 0x32, 0x70, 0x76, 0x53, 0x5f, 0x6a,
                0x1a, 0x00, 0x00, 0x00, 0x4f, 0x4d, 0x64, 0x6e, 0x42, 0x7a, 0x4b, 0x64, 0x66, 0x58,
                0x4c, 0x76, 0x59, 0x37, 0x38, 0x71, 0x57, 0x33, 0x67, 0x66, 0x34, 0x49, 0x45, 0x38,
                0x71, 0x75, 0x1b, 0x00, 0x00, 0x00, 0x65, 0x33, 0x7a, 0x4a, 0x33, 0x62, 0x61, 0x64,
                0x44, 0x63, 0x58, 0x42, 0x42, 0x37, 0x75, 0x62, 0x6f, 0x47, 0x34, 0x56, 0x38, 0x55,
                0x32, 0x76, 0x4a, 0x52, 0x63,
            ];

            tcp_stream.send(x.into()).await.unwrap();

            tcp_stream.next().await;
        });
    }
}
