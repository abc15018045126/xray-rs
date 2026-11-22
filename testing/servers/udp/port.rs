use tokio::net::UdpSocket;

pub async fn pick_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral UDP port");
    let port = socket.local_addr().expect("local addr").port();
    drop(socket);
    port
}
