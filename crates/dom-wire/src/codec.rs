//! Noise-encrypted message codec for tokio streams.
//!
//! # Transport fragmentation (post-handshake)
//!
//! A logical [`WireMessage`] can be larger than a single Noise transport frame:
//! `snow` rejects any plaintext above `NOISE_MAX_MSG` (65535), so the usable
//! plaintext per frame is `CHUNK = NOISE_MAX_MSG - 16 = 65519` (16 bytes are the
//! AEAD tag). An IBD `Headers` response at a serving tip above ~252 blocks, or a
//! full `Block` (up to `MAX_BLOCK_SERIALIZED_SIZE`, 16 MiB), exceeds that.
//!
//! To send a logical message with plaintext `P = msg.to_bytes()` we build a
//! length-prefixed stream `framed = u32_le(P.len()) ++ P` and split it into
//! consecutive `≤ CHUNK`-byte chunks. Each chunk is encrypted with its own
//! `write_message` and written as one length-prefixed transport frame (see
//! [`write_framed`]). So one logical message is 1+ Noise frames; the first frame
//! begins with the 4-byte total length of `P`.
//!
//! On receive we read frames, decrypt each, and append the plaintext to a
//! reassembly buffer `acc`. As soon as `acc` holds the 4-byte prefix we learn
//! the total length — validated against the compiled codec ceiling BEFORE growing
//! further — and the message is complete when `acc.len() == 4 + total`.
//!
//! # Cancel-safety (recv)
//!
//! [`NoiseCodec::recv`] is used as a `tokio::select!` branch and may be dropped
//! mid-message. ALL reassembly state lives on the struct — the per-frame
//! [`ReadState`], the `acc` buffer, and the parsed `expected` total — so a
//! dropped + restarted `recv` resumes exactly. INVARIANT: there is NO `.await`
//! between `read_message` (decrypt) and appending the plaintext to `acc`; the
//! only await in the recv loop is the cancel-safe frame read. This keeps the
//! Noise receive nonce in lockstep with the sender's per-frame writes even
//! across cancellation — each frame is decrypted exactly once.
//!
//! # Atomicity (send)
//!
//! [`NoiseCodec::send`] writes every frame for one logical message and is NOT
//! cancel-safe: if it is interrupted or errors mid-message the stream is
//! desynchronized and the caller MUST drop the connection. In the node message
//! loop `send` only runs inside `select!` branch *bodies* (which run to
//! completion), never as a cancellable branch future, so logical messages never
//! interleave on the wire.

use crate::handshake::{read_framed_cancel_safe, write_framed, ReadState, NOISE_MAX_MSG};
use crate::message::{WireMessage, MAX_MESSAGE_PAYLOAD};
use dom_core::{DomError, PeerMisbehavior, MAX_LOGICAL_MSG_BYTES};
use snow::TransportState;

/// Maximum plaintext bytes per Noise transport frame. The frame ciphertext is
/// `chunk.len() + 16` (AEAD tag), which must stay `≤ NOISE_MAX_MSG`.
const CHUNK: usize = NOISE_MAX_MSG - 16; // 65519

/// Reassembly ceiling for this compiled protocol surface. Ordinary builds keep
/// the global block-sized bound. The feature-gated candidate-v2 transport must
/// additionally fit one bounded witness bundle plus the 13-byte wire frame.
/// The payload parser still enforces the tighter command-specific lengths.
const MAX_CODEC_LOGICAL_MSG_BYTES: usize = if MAX_MESSAGE_PAYLOAD + 13 > MAX_LOGICAL_MSG_BYTES {
    MAX_MESSAGE_PAYLOAD + 13
} else {
    MAX_LOGICAL_MSG_BYTES
};

/// Encrypted connection wrapper.
pub struct NoiseCodec {
    transport: TransportState,
    network_magic: u32,
    /// Authenticated remote Noise static key. This is the stable peer identity
    /// available from the existing Noise XX handshake (no wire-format change).
    peer_id: Option<[u8; 32]>,
    /// Cancel-safe per-frame read state (resumes a partially-read frame).
    read_state: ReadState,
    /// Reassembly buffer for the in-progress logical message: the decrypted
    /// `framed` stream (`u32_le(total) ++ plaintext`). Persisted across recv
    /// cancellation; cleared only when a full message is returned (or on error).
    acc: Vec<u8>,
    /// `Some(4 + total_len)` once the 4-byte length prefix has been received and
    /// validated; `None` until then. The message is complete when
    /// `acc.len() == expected`.
    expected: Option<usize>,
    /// Per-frame idle deadline retained across `tokio::select!` cancellation.
    /// Without persistent state, every ping/maintenance tick could recreate
    /// `recv` and indefinitely postpone an otherwise finite idle timeout.
    read_deadline: Option<tokio::time::Instant>,
}

impl NoiseCodec {
    /// Create from a completed Noise handshake.
    pub fn new(transport: TransportState, network_magic: u32) -> Self {
        let peer_id = transport
            .get_remote_static()
            .and_then(|key| <[u8; 32]>::try_from(key).ok());
        Self {
            transport,
            network_magic,
            peer_id,
            read_state: ReadState::Idle,
            acc: Vec::new(),
            expected: None,
            read_deadline: None,
        }
    }

    /// Return the authenticated remote Noise static key used as PeerId.
    pub fn peer_id(&self) -> Option<[u8; 32]> {
        self.peer_id
    }

    /// Encrypt and send a logical message, fragmented across one or more Noise
    /// transport frames.
    ///
    /// NOT cancel-safe: writes all frames for the message. If interrupted or
    /// errored mid-message the connection is desynchronized and the caller MUST
    /// drop it. See the module docs for why this is safe in the node loop.
    pub async fn send(
        &mut self,
        stream: &mut tokio::net::TcpStream,
        msg: &WireMessage,
    ) -> Result<(), DomError> {
        if msg.payload.len() > MAX_MESSAGE_PAYLOAD {
            return Err(DomError::Invalid(format!(
                "outgoing payload {} bytes exceeds MAX_MESSAGE_PAYLOAD {MAX_MESSAGE_PAYLOAD}",
                msg.payload.len()
            )));
        }
        let command_limit = msg.command.max_payload_len();
        if msg.payload.len() > command_limit {
            return Err(DomError::Invalid(format!(
                "outgoing {:?} payload {} bytes exceeds command limit {command_limit}",
                msg.command,
                msg.payload.len()
            )));
        }
        let plaintext = msg.to_bytes();
        if plaintext.len() > MAX_CODEC_LOGICAL_MSG_BYTES {
            return Err(DomError::Invalid(format!(
                "outgoing message {} bytes exceeds codec limit {MAX_CODEC_LOGICAL_MSG_BYTES}",
                plaintext.len()
            )));
        }
        // framed = u32_le(total) ++ plaintext, split into ≤ CHUNK-byte pieces.
        let mut framed = Vec::with_capacity(4 + plaintext.len());
        framed.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        framed.extend_from_slice(&plaintext);
        let write_timeout = crate::handshake::write_timeout_secs();
        for chunk in framed.chunks(CHUNK) {
            let mut ciphertext = vec![0u8; chunk.len() + 16]; // +16 for AEAD tag
            let len = self
                .transport
                .write_message(chunk, &mut ciphertext)
                .map_err(|e| DomError::Internal(format!("noise encrypt: {e}")))?;
            // Anti-slowloris: bound each frame write. A peer that stops reading
            // fills our send buffer and would otherwise block `write_all`
            // forever, pinning this task. Mirrors the per-frame read timeout in
            // `recv`. NOT cancel-safe (see method docs): on timeout the stream
            // is desynchronized, so the caller MUST drop the connection.
            tokio::time::timeout(
                tokio::time::Duration::from_secs(write_timeout),
                write_framed(stream, &ciphertext[..len]),
            )
            .await
            .map_err(|_| {
                DomError::peer_misbehavior(
                    PeerMisbehavior::WriteTimeout,
                    format!("write timeout after {write_timeout}s"),
                )
            })??;
        }
        Ok(())
    }

    /// Receive and decrypt one logical message, reassembling fragments.
    ///
    /// Resumable across `tokio::select!` cancellation: all progress is kept on
    /// `self`. The idle timeout applies per frame.
    pub async fn recv(
        &mut self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<WireMessage, DomError> {
        self.recv_with_idle_timeout(
            stream,
            tokio::time::Duration::from_secs(crate::handshake::IDLE_TIMEOUT_SECS),
        )
        .await
    }

    /// Receive one logical message with a caller-selected per-frame idle
    /// timeout. IBD uses a more tolerant liveness window while normal relay
    /// sessions retain the established 60-second policy.
    pub async fn recv_with_idle_timeout(
        &mut self,
        stream: &mut tokio::net::TcpStream,
        idle_timeout: tokio::time::Duration,
    ) -> Result<WireMessage, DomError> {
        loop {
            // The ONLY await in this loop. Cancel-safe: partial-frame progress is
            // in `self.read_state`, and whole-frame progress is in `self.acc` /
            // `self.expected`, so a dropped recv resumes here.
            let deadline = *self
                .read_deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + idle_timeout);
            let ciphertext = tokio::time::timeout_at(
                deadline,
                read_framed_cancel_safe(stream, &mut self.read_state),
            )
            .await
            .map_err(|_| {
                self.reset_reassembly();
                DomError::PolicyRejected(format!("idle timeout after {}s", idle_timeout.as_secs()))
            })??;
            // A complete transport frame is progress. The next frame gets one
            // fresh idle interval, and this deadline again survives select
            // cancellation while that frame is partial or absent.
            self.read_deadline = Some(tokio::time::Instant::now() + idle_timeout);

            // INVARIANT: no `.await` between decrypt and the `acc` append, so the
            // receive nonce advances exactly once per frame even under
            // cancellation.
            let mut plaintext = vec![0u8; ciphertext.len()];
            let n = self
                .transport
                .read_message(&ciphertext, &mut plaintext)
                .map_err(|e| DomError::Invalid(format!("noise decrypt: {e}")))?;

            // The sender uses canonical CHUNK-sized fragmentation: every frame
            // is full except the final frame. Reject tiny-frame fragmentation
            // before accumulation; otherwise one bounded logical message could
            // require millions of AEAD operations and repeatedly refresh the
            // per-frame idle deadline.
            if self.expected.is_none() && n < 4 {
                self.reset_reassembly();
                return Err(DomError::Malformed(
                    "first logical transport frame is shorter than length prefix".into(),
                ));
            }
            if let Some(expected) = self.expected {
                let remaining = expected.checked_sub(self.acc.len()).ok_or_else(|| {
                    DomError::Malformed("transport reassembly accounting underflow".into())
                })?;
                if n != remaining.min(CHUNK) {
                    self.reset_reassembly();
                    return Err(DomError::Malformed(
                        "noncanonical logical transport fragmentation".into(),
                    ));
                }
            }
            self.acc.extend_from_slice(&plaintext[..n]);

            // Learn and validate the total length as soon as the prefix is in.
            // We never pre-allocate `total` bytes from an unvalidated value — the
            // buffer only grows by ≤ CHUNK per frame and is capped below.
            if self.expected.is_none() && self.acc.len() >= 4 {
                let total = u32::from_le_bytes(self.acc[0..4].try_into().unwrap()) as usize;
                if total > MAX_CODEC_LOGICAL_MSG_BYTES {
                    self.reset_reassembly();
                    return Err(DomError::Malformed(format!(
                        "logical message {total} bytes exceeds codec limit \
                         {MAX_CODEC_LOGICAL_MSG_BYTES}"
                    )));
                }
                let expected = 4 + total;
                self.expected = Some(expected);
                if n != expected.min(CHUNK) {
                    self.reset_reassembly();
                    return Err(DomError::Malformed(
                        "noncanonical first logical transport fragment".into(),
                    ));
                }
                // The canonical first fragment also contains the complete
                // WireMessage header. Reject an unknown command, wrong network
                // or inconsistent inner length before receiving a potentially
                // block-sized remainder.
                if total >= 13 {
                    let magic = u32::from_le_bytes(self.acc[4..8].try_into().unwrap());
                    if magic != self.network_magic {
                        self.reset_reassembly();
                        return Err(DomError::Invalid("wire magic mismatch".into()));
                    }
                    let command = match crate::message::Command::from_byte(self.acc[8]) {
                        Ok(command) => command,
                        Err(error) => {
                            self.reset_reassembly();
                            return Err(error);
                        }
                    };
                    let payload_len =
                        u32::from_le_bytes(self.acc[9..13].try_into().unwrap()) as usize;
                    if payload_len > MAX_MESSAGE_PAYLOAD
                        || payload_len > command.max_payload_len()
                        || total != 13 + payload_len
                    {
                        self.reset_reassembly();
                        return Err(DomError::Malformed(
                            "logical and wire message lengths disagree".into(),
                        ));
                    }
                }
            }

            if let Some(expected) = self.expected {
                if self.acc.len() > expected {
                    // A well-behaved sender ends the last frame exactly at the
                    // message boundary; overrun means a malformed peer.
                    self.reset_reassembly();
                    return Err(DomError::Malformed(
                        "transport reassembly overran the declared length".into(),
                    ));
                }
                if self.acc.len() == expected {
                    let acc = std::mem::take(&mut self.acc);
                    self.expected = None;
                    self.read_deadline = None;
                    // acc == [u32_le(total) ++ plaintext]; the message is acc[4..].
                    return WireMessage::from_bytes(&acc[4..], self.network_magic);
                }
            }
            // Not complete yet — read the next frame.
        }
    }

    /// Clear in-progress reassembly state. Called on a fatal recv error; the
    /// connection should be dropped after any recv error regardless.
    fn reset_reassembly(&mut self) {
        self.acc.clear();
        self.expected = None;
        self.read_state = ReadState::Idle;
        self.read_deadline = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{
        generate_static_keypair, perform_handshake_initiator, perform_handshake_responder,
    };
    use crate::message::{Command, HeadersPayload};

    const TEST_MAGIC: u32 = dom_core::NETWORK_MAGIC_REGTEST;
    const TEST_CHAIN_ID: [u8; 32] = [0x42u8; 32];

    /// Stand up a real Noise_XX session over a loopback TCP pair and return both
    /// raw `TransportState`s + their streams.
    async fn connected_transports() -> (
        tokio::net::TcpStream,
        TransportState,
        tokio::net::TcpStream,
        TransportState,
    ) {
        let (ipriv, _) = generate_static_keypair();
        let (rpriv, _) = generate_static_keypair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let t = perform_handshake_responder(&mut s, &rpriv, TEST_MAGIC, &TEST_CHAIN_ID)
                .await
                .unwrap();
            (s, t)
        });

        let mut istream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let it = perform_handshake_initiator(&mut istream, &ipriv, TEST_MAGIC, &TEST_CHAIN_ID)
            .await
            .unwrap();
        let (rstream, rt) = responder.await.unwrap();
        (istream, it, rstream, rt)
    }

    /// Same as above but wrapped in `NoiseCodec`s.
    async fn connected_codecs() -> (
        tokio::net::TcpStream,
        NoiseCodec,
        tokio::net::TcpStream,
        NoiseCodec,
    ) {
        let (a, at, b, bt) = connected_transports().await;
        (
            a,
            NoiseCodec::new(at, TEST_MAGIC),
            b,
            NoiseCodec::new(bt, TEST_MAGIC),
        )
    }

    /// Build a Tx message whose serialized plaintext (`to_bytes()`) is exactly
    /// `plaintext_len` bytes (13-byte envelope + payload).
    fn tx_msg_with_plaintext(plaintext_len: usize) -> WireMessage {
        assert!(plaintext_len >= 13);
        WireMessage {
            magic: TEST_MAGIC,
            command: Command::Tx,
            payload: vec![0xABu8; plaintext_len - 13],
        }
    }

    /// Manually fragment `msg` into Noise frames using a raw transport (mirrors
    /// `NoiseCodec::send`'s framing). Lets tests drive the wire byte-by-byte.
    fn fragment(transport: &mut TransportState, msg: &WireMessage) -> Vec<Vec<u8>> {
        let plaintext = msg.to_bytes();
        let mut framed = Vec::with_capacity(4 + plaintext.len());
        framed.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        framed.extend_from_slice(&plaintext);
        framed
            .chunks(CHUNK)
            .map(|c| {
                let mut ct = vec![0u8; c.len() + 16];
                let n = transport.write_message(c, &mut ct).unwrap();
                ct.truncate(n);
                ct
            })
            .collect()
    }

    #[tokio::test]
    async fn roundtrip_various_plaintext_sizes() {
        let (mut a, mut ca, mut b, mut cb) = connected_codecs().await;
        // tiny (1 frame); CHUNK boundary either side of the 4-byte prefix;
        // the spec's 65519/65520; an exact 2*CHUNK; and the 1008-header size.
        // send and recv run concurrently (join!): a large message would block
        // send() on TCP backpressure if nobody were draining the other end.
        for &p in &[13usize, 65515, 65516, 65519, 65520, 2 * 65519, 262095] {
            let msg = tx_msg_with_plaintext(p);
            let (sr, rr) = tokio::join!(ca.send(&mut a, &msg), cb.recv(&mut b));
            sr.unwrap();
            let got = rr.unwrap();
            assert_eq!(got.command, Command::Tx);
            assert_eq!(got.payload, msg.payload, "round-trip mismatch at P={p}");
            assert_eq!(got.to_bytes().len(), p);
        }
    }

    #[tokio::test]
    async fn roundtrip_max_block_size() {
        let (mut a, mut ca, mut b, mut cb) = connected_codecs().await;
        // P = 16 MiB exactly (largest legit message: a full Block).
        let p = 16 * 1024 * 1024;
        let msg = WireMessage {
            magic: TEST_MAGIC,
            command: Command::Block,
            payload: vec![0x5Au8; p - 13],
        };
        assert!(msg.to_bytes().len() <= MAX_CODEC_LOGICAL_MSG_BYTES);
        let (sr, rr) = tokio::join!(ca.send(&mut a, &msg), cb.recv(&mut b));
        sr.unwrap();
        let got = rr.unwrap();
        assert_eq!(got.command, Command::Block);
        assert_eq!(got.payload.len(), p - 13);
        assert_eq!(got.payload, msg.payload);
    }

    /// The exact regression: a real `Headers` message carrying 1008 headers
    /// (262,095-byte plaintext) — which used to overflow `write_message`.
    #[tokio::test]
    async fn headers_1008_roundtrip_regression() {
        let (mut a, mut ca, mut b, mut cb) = connected_codecs().await;
        let headers = vec![vec![0u8; 256]; 1008];
        let payload = HeadersPayload {
            headers: headers.clone(),
        }
        .to_bytes()
        .unwrap();
        let msg = WireMessage {
            magic: TEST_MAGIC,
            command: Command::Headers,
            payload,
        };
        assert!(
            msg.to_bytes().len() > NOISE_MAX_MSG,
            "this size must exceed a single Noise frame to be a real regression"
        );
        let (sr, rr) = tokio::join!(ca.send(&mut a, &msg), cb.recv(&mut b));
        sr.unwrap();
        let got = rr.unwrap();
        let parsed = HeadersPayload::from_bytes(&got.payload).unwrap();
        assert_eq!(parsed.headers.len(), 1008);
        assert_eq!(parsed.headers, headers);
    }

    /// Two messages back-to-back decrypt correctly (nonce stays in sync).
    #[tokio::test]
    async fn sequential_messages_keep_nonce_in_sync() {
        let (mut a, mut ca, mut b, mut cb) = connected_codecs().await;
        let m1 = tx_msg_with_plaintext(2 * 65519 + 100); // 3 frames
        let m2 = tx_msg_with_plaintext(50); // 1 frame
                                            // Drive both sends concurrently with both receives so the 3-frame m1
                                            // can't block send() on backpressure.
        let send_fut = async {
            ca.send(&mut a, &m1).await.unwrap();
            ca.send(&mut a, &m2).await.unwrap();
        };
        let recv_fut = async {
            let g1 = cb.recv(&mut b).await.unwrap();
            let g2 = cb.recv(&mut b).await.unwrap();
            (g1, g2)
        };
        let ((), (g1, g2)) = tokio::join!(send_fut, recv_fut);
        assert_eq!(g1.payload, m1.payload);
        assert_eq!(g2.payload, m2.payload);
    }

    /// DoS: a first frame declaring a total length above the cap is rejected
    /// immediately, without allocating the declared size.
    #[tokio::test]
    async fn recv_rejects_oversized_declared_length() {
        let (mut a, mut sender_t, mut b, rt) = connected_transports().await;
        let mut cb = NoiseCodec::new(rt, TEST_MAGIC);

        // Craft one frame whose plaintext begins with a bogus huge total length.
        let bogus_total = (MAX_CODEC_LOGICAL_MSG_BYTES + 1) as u32;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&bogus_total.to_le_bytes());
        chunk.extend_from_slice(&[0u8; 8]); // a little payload, not the full claim
        let mut ct = vec![0u8; chunk.len() + 16];
        let n = sender_t.write_message(&chunk, &mut ct).unwrap();
        write_framed(&mut a, &ct[..n]).await.unwrap();

        let err = cb.recv(&mut b).await.unwrap_err();
        assert!(
            matches!(err, DomError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn recv_rejects_tiny_first_fragment_before_accumulation() {
        let (mut a, mut sender_t, mut b, rt) = connected_transports().await;
        let mut cb = NoiseCodec::new(rt, TEST_MAGIC);
        let mut ciphertext = vec![0u8; 17];
        let n = sender_t.write_message(&[0x01], &mut ciphertext).unwrap();
        write_framed(&mut a, &ciphertext[..n]).await.unwrap();

        let error = cb.recv(&mut b).await.unwrap_err();
        assert!(matches!(error, DomError::Malformed(_)));
        assert!(cb.acc.is_empty());
    }

    #[tokio::test]
    async fn recv_rejects_unknown_command_from_first_fragment() {
        let (mut a, mut sender_t, mut b, rt) = connected_transports().await;
        let mut cb = NoiseCodec::new(rt, TEST_MAGIC);
        let total = CHUNK + 100;
        let mut fragment = vec![0u8; CHUNK];
        fragment[..4].copy_from_slice(&(total as u32).to_le_bytes());
        fragment[4..8].copy_from_slice(&TEST_MAGIC.to_le_bytes());
        fragment[8] = 0xff;
        fragment[9..13].copy_from_slice(&((total - 13) as u32).to_le_bytes());
        let mut ciphertext = vec![0u8; fragment.len() + 16];
        let n = sender_t.write_message(&fragment, &mut ciphertext).unwrap();
        write_framed(&mut a, &ciphertext[..n]).await.unwrap();

        let error = cb.recv(&mut b).await.unwrap_err();
        assert!(matches!(error, DomError::Malformed(_)));
        assert!(cb.acc.is_empty());
    }

    /// A cheap command cannot consume the global block-sized allowance. The
    /// receiver rejects it from the first canonical fragment, before waiting
    /// for or accumulating the declared remainder.
    #[tokio::test]
    async fn recv_rejects_command_oversize_from_first_fragment() {
        let (mut a, mut sender_t, mut b, rt) = connected_transports().await;
        let mut cb = NoiseCodec::new(rt, TEST_MAGIC);
        let total = CHUNK + 100;
        let payload_len = total - 13;
        assert!(payload_len > Command::Ping.max_payload_len());
        assert!(payload_len < MAX_MESSAGE_PAYLOAD);
        let mut fragment = vec![0u8; CHUNK];
        fragment[..4].copy_from_slice(&(total as u32).to_le_bytes());
        fragment[4..8].copy_from_slice(&TEST_MAGIC.to_le_bytes());
        fragment[8] = Command::Ping as u8;
        fragment[9..13].copy_from_slice(&(payload_len as u32).to_le_bytes());
        let mut ciphertext = vec![0u8; fragment.len() + 16];
        let n = sender_t.write_message(&fragment, &mut ciphertext).unwrap();
        write_framed(&mut a, &ciphertext[..n]).await.unwrap();

        let error = cb.recv(&mut b).await.unwrap_err();
        assert!(matches!(error, DomError::Malformed(_)));
        assert!(cb.acc.is_empty());
    }

    #[tokio::test]
    async fn send_rejects_command_oversize_before_transport_write() {
        let (mut a, mut ca, _b, _cb) = connected_codecs().await;
        let message = WireMessage {
            magic: TEST_MAGIC,
            command: Command::Ping,
            payload: vec![0; Command::Ping.max_payload_len() + 1],
        };
        let error = ca.send(&mut a, &message).await.unwrap_err();
        assert!(matches!(error, DomError::Invalid(_)));
    }

    #[tokio::test]
    async fn idle_deadline_survives_repeated_recv_cancellation() {
        let (_a, _sender_t, mut b, rt) = connected_transports().await;
        let mut cb = NoiseCodec::new(rt, TEST_MAGIC);
        let idle = tokio::time::Duration::from_millis(20);

        let error = loop {
            tokio::select! {
                result = cb.recv_with_idle_timeout(&mut b, idle) => break result.unwrap_err(),
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(3)) => {}
            }
        };
        assert!(matches!(error, DomError::PolicyRejected(_)));
        assert!(cb.read_deadline.is_none());
    }

    /// Cancel-safety: a multi-frame message sent slowly is received while
    /// `recv()` is repeatedly cancelled on a short timeout. The codec state must
    /// persist on the struct so reassembly resumes, and a follow-up message must
    /// still decrypt (nonce in sync after all the cancellations).
    #[tokio::test]
    async fn recv_is_cancel_safe_across_frames() {
        let (mut a, mut sender_t, mut b, rt) = connected_transports().await;
        let mut cb = NoiseCodec::new(rt, TEST_MAGIC);

        let m1 = tx_msg_with_plaintext(2 * 65519 + 7); // 3 frames
        let m2 = tx_msg_with_plaintext(40); // 1 frame
                                            // Pre-encrypt both messages' frames in order on the same transport, so
                                            // the nonce sequence matches what the receiver expects.
        let mut frames = fragment(&mut sender_t, &m1);
        frames.extend(fragment(&mut sender_t, &m2));

        // Sender task: write each frame with a delay, so the receiver's short
        // cancel timeout lands between (and during) frames.
        let sender = tokio::spawn(async move {
            for f in frames {
                write_framed(&mut a, &f).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            a // keep the stream alive until the receiver is done
        });

        // Receive m1 while constantly cancelling recv() on a 3 ms timeout.
        let g1 = loop {
            tokio::select! {
                r = cb.recv(&mut b) => break r.unwrap(),
                _ = tokio::time::sleep(std::time::Duration::from_millis(3)) => { /* cancel + retry */ }
            }
        };
        assert_eq!(
            g1.payload, m1.payload,
            "reassembly failed across cancellation"
        );

        // The follow-up message must still decrypt: nonce stayed in lockstep.
        let g2 = cb.recv(&mut b).await.unwrap();
        assert_eq!(
            g2.payload, m2.payload,
            "nonce desynchronized after cancellation"
        );

        let _keepalive = sender.await.unwrap();
    }
}
