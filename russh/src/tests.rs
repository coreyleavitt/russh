#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Allow unwraps, expects and panics in the test suite

use futures::Future;

use super::*;

mod compress {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::keys::ssh_key::rand_core::OsRng;
    use keys::PrivateKeyWithHashAlg;
    use log::debug;
    use ssh_key::PrivateKey;

    use super::server::{Server as _, Session};
    use super::*;
    use crate::server::Msg;

    #[tokio::test]
    async fn compress_local_test() {
        let _ = env_logger::try_init();

        let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let mut config = server::Config::default();
        config.preferred = Preferred::COMPRESSED;
        config.inactivity_timeout = None; // Some(std::time::Duration::from_secs(3));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);
        let mut sh = Server {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            let server = sh.new_client(socket.peer_addr().ok());
            server::run_stream(config, socket, server).await.unwrap();
        });

        let mut config = client::Config::default();
        config.preferred = Preferred::COMPRESSED;
        let config = Arc::new(config);

        let mut session = client::connect(config, addr, Client {}).await.unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap()
            .success();
        assert!(authenticated);
        let mut channel = session.channel_open_session().await.unwrap();

        let data = &b"Hello, world!"[..];
        channel.data(data).await.unwrap();
        let msg = channel.wait().await.unwrap();
        match msg {
            ChannelMsg::Data { data: msg_data } => {
                assert_eq!(*data, *msg_data)
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    }

    #[derive(Clone)]
    struct Server {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), super::server::Handle>>>,
        id: usize,
    }

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    impl server::Handler for Server {
        type Error = super::Error;

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel.id()), session.handle());
            }
            Ok(true)
        }
        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &crate::keys::ssh_key::PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            debug!("auth_publickey");
            Ok(server::Auth::Accept)
        }
        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("server data = {:?}", std::str::from_utf8(data));
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    struct Client {}

    impl client::Handler for Client {
        type Error = super::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &crate::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            // println!("check_server_key: {:?}", server_public_key);
            Ok(true)
        }
    }
}

mod channels {
    use elliptic_curve::rand_core::OsRng;
    use keys::PrivateKeyWithHashAlg;
    use server::Session;
    use ssh_key::PrivateKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn test_session<RC, RS, CH, SH, F1, F2>(
        client_handler: CH,
        server_handler: SH,
        run_client: RC,
        run_server: RS,
    ) where
        RC: FnOnce(crate::client::Handle<CH>) -> F1 + Send + Sync + 'static,
        RS: FnOnce(crate::server::Handle) -> F2 + Send + Sync + 'static,
        F1: Future<Output = crate::client::Handle<CH>> + Send + Sync + 'static,
        F2: Future<Output = crate::server::Handle> + Send + Sync + 'static,
        CH: crate::client::Handler + Send + Sync + 'static,
        SH: crate::server::Handler + Send + Sync + 'static,
    {
        use std::sync::Arc;

        use crate::*;

        let _ = env_logger::try_init();

        let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let server_join = tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();

            server::run_stream(config, socket, server_handler)
                .await
                .map_err(|_| ())
                .unwrap()
        });

        let client_join = tokio::spawn(async move {
            let config = Arc::new(client::Config::default());
            let mut session = client::connect(config, addr, client_handler)
                .await
                .map_err(|_| ())
                .unwrap();
            let authenticated = session
                .authenticate_publickey(
                    std::env::var("USER").unwrap_or("user".to_owned()),
                    PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
                )
                .await
                .unwrap();
            assert!(authenticated.success());
            session
        });

        let (server_session, client_session) = tokio::join!(server_join, client_join);
        let client_handle = tokio::spawn(run_client(client_session.unwrap()));
        let server_handle = tokio::spawn(run_server(server_session.unwrap().handle()));

        let (server_session, client_session) = tokio::join!(server_handle, client_handle);
        assert!(server_session.is_ok());
        assert!(client_session.is_ok());
        drop(client_session);
        drop(server_session);
    }

    #[tokio::test]
    async fn test_reject_server_session_channel() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            did_auth: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl ServerHandle {
            fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.did_auth = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }
            async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
                if let Some(a) = self.did_auth.take() {
                    a.send(()).unwrap();
                }
                Ok(())
            }
        }

        let mut sh = ServerHandle { did_auth: None };
        let a = sh.get_auth_waiter();
        test_session(
            Client {},
            sh,
            |c| async move { c },
            |s| async move {
                a.await.unwrap();
                // Server-initiated session channels should be rejected by the client
                // (RFC 4254 Section 6.1: sessions are opened by the client)
                let result = s.channel_open_session().await;
                assert!(
                    result.is_err(),
                    "Server-initiated session channel should be rejected"
                );
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_streams() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl ServerHandle {
            fn get_channel_waiter(
                &mut self,
            ) -> tokio::sync::oneshot::Receiver<Channel<server::Msg>> {
                let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
                self.channel = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                _session: &mut server::Session,
            ) -> Result<bool, Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {a:?}");
                    a.send(channel).unwrap();
                }
                Ok(true)
            }
        }

        let mut sh = ServerHandle { channel: None };
        let scw = sh.get_channel_waiter();

        test_session(
            Client {},
            sh,
            |client| async move {
                let ch = client.channel_open_session().await.unwrap();
                let mut stream = ch.into_stream();
                stream.write_all(&b"request"[..]).await.unwrap();

                let mut buf = Vec::new();
                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"response"[..]);

                stream.write_all(&b"reply"[..]).await.unwrap();

                client
            },
            |server| async move {
                let channel = scw.await.unwrap();
                let mut stream = channel.into_stream();

                let mut buf = Vec::new();
                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"request"[..]);

                stream.write_all(&b"response"[..]).await.unwrap();

                buf.clear();

                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"reply"[..]);

                server
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_objects() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {}

        impl ServerHandle {}

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                mut channel: Channel<server::Msg>,
                _session: &mut Session,
            ) -> Result<bool, Self::Error> {
                tokio::spawn(async move {
                    while let Some(msg) = channel.wait().await {
                        match msg {
                            ChannelMsg::Data { data } => {
                                channel.data(&data[..]).await.unwrap();
                                channel.close().await.unwrap();
                                break;
                            }
                            _ => {}
                        }
                    }
                });
                Ok(true)
            }
        }

        let sh = ServerHandle {};
        test_session(
            Client {},
            sh,
            |c| async move {
                let mut ch = c.channel_open_session().await.unwrap();
                ch.data(&b"hello world!"[..]).await.unwrap();

                let msg = ch.wait().await.unwrap();
                if let ChannelMsg::Data { data } = msg {
                    assert_eq!(&data[..], &b"hello world!"[..]);
                } else {
                    panic!("Unexpected message {msg:?}");
                }

                assert!(ch.wait().await.is_none());
                c
            },
            |s| async move { s },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_window_size() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl ServerHandle {
            fn get_channel_waiter(
                &mut self,
            ) -> tokio::sync::oneshot::Receiver<Channel<server::Msg>> {
                let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
                self.channel = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                _session: &mut server::Session,
            ) -> Result<bool, Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {a:?}");
                    a.send(channel).unwrap();
                }
                Ok(true)
            }
        }

        let mut sh = ServerHandle { channel: None };
        let scw = sh.get_channel_waiter();

        test_session(
            Client {},
            sh,
            |client| async move {
                let ch = client.channel_open_session().await.unwrap();

                let mut writer_1 = ch.make_writer();
                let jh_1 = tokio::spawn(async move {
                    let buf = [1u8; 1024 * 64];
                    assert!(writer_1.write_all(&buf).await.is_ok());
                });
                let mut writer_2 = ch.make_writer();
                let jh_2 = tokio::spawn(async move {
                    let buf = [2u8; 1024 * 64];
                    assert!(writer_2.write_all(&buf).await.is_ok());
                });

                assert!(tokio::try_join!(jh_1, jh_2).is_ok());

                client
            },
            |server| async move {
                let mut channel = scw.await.unwrap();

                let mut total_data = 2 * 1024 * 64;
                while let Some(msg) = channel.wait().await {
                    match msg {
                        ChannelMsg::Data { data } => {
                            total_data -= data.len();
                            if total_data == 0 {
                                break;
                            }
                        }
                        _ => panic!("Unexpected message {msg:?}"),
                    }
                }

                server
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_reject_server_direct_tcpip() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            did_auth: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl ServerHandle {
            fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.did_auth = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }
            async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
                if let Some(a) = self.did_auth.take() {
                    a.send(()).unwrap();
                }
                Ok(())
            }
        }

        let mut sh = ServerHandle { did_auth: None };
        let a = sh.get_auth_waiter();
        test_session(
            Client {},
            sh,
            |c| async move { c },
            |s| async move {
                a.await.unwrap();
                // Server-initiated direct-tcpip channels should be rejected
                // (RFC 4254 Section 7.2: direct-tcpip is client-to-server only)
                let result = s
                    .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 12345)
                    .await;
                assert!(
                    result.is_err(),
                    "Server-initiated direct-tcpip should be rejected"
                );
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_reject_forwarded_tcpip_without_request() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            did_auth: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl ServerHandle {
            fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.did_auth = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }
            async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
                if let Some(a) = self.did_auth.take() {
                    a.send(()).unwrap();
                }
                Ok(())
            }
        }

        let mut sh = ServerHandle { did_auth: None };
        let a = sh.get_auth_waiter();
        test_session(
            Client {},
            sh,
            |c| async move { c },
            |s| async move {
                a.await.unwrap();
                // forwarded-tcpip without a prior tcpip-forward request should be rejected
                let result = s
                    .channel_open_forwarded_tcpip("127.0.0.1", 8080, "10.0.0.1", 54321)
                    .await;
                assert!(
                    result.is_err(),
                    "forwarded-tcpip without prior request should be rejected"
                );
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_accept_forwarded_tcpip_with_request() {
        use std::sync::Arc;
        use tokio::sync::Notify;

        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            forward_ready: Arc<Notify>,
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn tcpip_forward(
                &mut self,
                _address: &str,
                _port: &mut u32,
                _session: &mut Session,
            ) -> Result<bool, Self::Error> {
                // Accept the forward request, then signal that it's ready
                self.forward_ready.notify_one();
                Ok(true)
            }
        }

        let forward_ready = Arc::new(Notify::new());
        let forward_ready_server = forward_ready.clone();

        let sh = ServerHandle {
            forward_ready: forward_ready_server,
        };

        let forward_ready_client = forward_ready.clone();
        test_session(
            Client {},
            sh,
            |mut c| async move {
                // Request TCP/IP forwarding first
                let port = c.tcpip_forward("127.0.0.1", 8080).await.unwrap();
                assert_eq!(port, 0); // server returns 0 for specific port requests
                c
            },
            |s| async move {
                // Wait for the forward request to be processed
                forward_ready_client.notified().await;
                // Small delay to ensure the client has processed the reply
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                // Now forwarded-tcpip should be accepted since client requested forwarding
                let result = s
                    .channel_open_forwarded_tcpip("127.0.0.1", 8080, "10.0.0.1", 54321)
                    .await;
                assert!(
                    result.is_ok(),
                    "forwarded-tcpip with prior request should be accepted"
                );
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_reject_x11_without_request() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            did_auth: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl ServerHandle {
            fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.did_auth = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }
            async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
                if let Some(a) = self.did_auth.take() {
                    a.send(()).unwrap();
                }
                Ok(())
            }
        }

        let mut sh = ServerHandle { did_auth: None };
        let a = sh.get_auth_waiter();
        test_session(
            Client {},
            sh,
            |c| async move { c },
            |s| async move {
                a.await.unwrap();
                // X11 channel without prior x11 request should be rejected
                let result = s.channel_open_x11("127.0.0.1", 6000).await;
                assert!(
                    result.is_err(),
                    "X11 channel without prior request should be rejected"
                );
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_cancel_removes_forwarding_state() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::Arc;

        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            state: Arc<AtomicU8>,
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn tcpip_forward(
                &mut self,
                _address: &str,
                _port: &mut u32,
                _session: &mut Session,
            ) -> Result<bool, Self::Error> {
                self.state.store(1, Ordering::SeqCst);
                Ok(true)
            }

            async fn cancel_tcpip_forward(
                &mut self,
                _address: &str,
                _port: u32,
                _session: &mut Session,
            ) -> Result<bool, Self::Error> {
                self.state.store(2, Ordering::SeqCst);
                Ok(true)
            }
        }

        let state = Arc::new(AtomicU8::new(0));

        let sh = ServerHandle {
            state: state.clone(),
        };

        let state_server = state.clone();

        test_session(
            Client {},
            sh,
            |mut c| async move {
                // Request forwarding, then cancel it
                let _port = c.tcpip_forward("127.0.0.1", 9090).await.unwrap();
                c.cancel_tcpip_forward("127.0.0.1", 9090).await.unwrap();
                // Give server time to attempt the channel open
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                c
            },
            |s| async move {
                // Wait until cancel has been processed
                while state_server.load(Ordering::SeqCst) < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                // Small delay to ensure client has processed the cancel reply
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                // After cancel, forwarded-tcpip should be rejected
                let result = s
                    .channel_open_forwarded_tcpip("127.0.0.1", 9090, "10.0.0.1", 54321)
                    .await;
                assert!(
                    result.is_err(),
                    "forwarded-tcpip after cancel should be rejected"
                );
                s
            },
        )
        .await;
    }
}

mod server_kex_junk {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;

    use super::server::Server as _;
    use super::*;

    #[tokio::test]
    async fn server_kex_junk_test() {
        let _ = env_logger::try_init();

        let config = server::Config::default();
        let config = Arc::new(config);
        let mut sh = Server {};

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            client_stream
                .write_all(b"SSH-2.0-Client_1.0\r\n")
                .await
                .unwrap();
            // Unexpected message pre-kex
            client_stream.write_all(&[0, 0, 0, 2, 0, 99]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });

        let (socket, _) = socket.accept().await.unwrap();
        let server = sh.new_client(socket.peer_addr().ok());
        let rs = server::run_stream(config, socket, server).await.unwrap();

        // May not panic
        assert!(rs.await.is_err());
    }

    #[derive(Clone)]
    struct Server {}

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for Server {
        type Error = super::Error;
    }
}
