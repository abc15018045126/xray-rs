use tokio::net::TcpListener;

pub async fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral TCP port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}
