use dom_rpc::{NodeHandle, RpcError, TxAdmission, UtxoInfo};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct EmptyNode;

impl NodeHandle for EmptyNode {
    fn chain_height(&self) -> u64 {
        0
    }
    fn mempool_size(&self) -> usize {
        0
    }
    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<dom_rpc::MempoolTxInfo> {
        None
    }
    fn submit_tx(&self, _: Vec<u8>) -> Result<TxAdmission, RpcError> {
        Err(RpcError::Rejected("test rejection".into()))
    }
    fn network(&self) -> &'static str {
        "regtest"
    }
    fn get_block_header(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    fn get_block_hash_at_height(&self, _: u64) -> Option<[u8; 32]> {
        None
    }
    fn get_utxo(&self, _: &[u8; 33]) -> Option<UtxoInfo> {
        None
    }
}

async fn spoofed_submit(addr: SocketAddr, spoofed_ip: &str) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /tx/submit HTTP/1.1\r\nHost: {addr}\r\nX-Forwarded-For: {spoofed_ip}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let status_line = std::str::from_utf8(&response)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// The production listener has no trusted-proxy allowlist. Forwarding headers
/// must therefore never select the governor key: all three TCP connections
/// below originate at one observed peer and share the two-request burst.
#[tokio::test]
async fn spoofed_forwarding_headers_cannot_evade_submit_rate_limit() {
    std::env::set_var("DOM_RPC_RATELIMIT_SUBMIT", "2");
    let listener = dom_rpc::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(dom_rpc::serve_with_token_until_shutdown(
        Arc::new(EmptyNode),
        listener,
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let statuses = tokio::join!(
        spoofed_submit(addr, "192.0.2.1"),
        spoofed_submit(addr, "198.51.100.2"),
        spoofed_submit(addr, "203.0.113.3"),
    );
    let statuses = [statuses.0, statuses.1, statuses.2];
    assert_eq!(
        statuses.iter().filter(|status| **status == 429).count(),
        1,
        "one shared peer-IP burst must reject exactly one request: {statuses:?}"
    );

    let _ = shutdown_tx.send(());
    server.await.unwrap().unwrap();
    std::env::remove_var("DOM_RPC_RATELIMIT_SUBMIT");
}
