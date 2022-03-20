pub use crate::body::Body;
use crate::message_socket::ReadError;
use crate::parser_utilities::parse_c_seq;
pub use crate::rtsp_machine::Data;
use crate::rtsp_machine::{
    DescribeResponse, DescribeResponseMessage, Media, Message, OnEvent, OptionsResponse,
    OptionsResponseMessage, PlayResponse, PlayResponseMessage, Response, RtspMachine,
    RtspMachineError, SetupResponse, SetupResponseMessage, UnauthorizedResponse,
    UnauthorizedResponseMessage,
};
#[allow(unused)]
use crate::{log_rtsp_message, log_rtsp_request, log_rtsp_response};
use futures::future::{BoxFuture, FutureExt};
use futures::lock::Mutex;
use futures::prelude::*;
use futures::stream::StreamExt;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
pub use rtsp_types::Version;
pub use rtsp_types::{Host, Url};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
pub use www_authenticate::Error as WwwAuthParseError;

const DEFAULT_MAXIMUM_CONNECTION_RETRIES: u32 = 3;
const DEFAULT_MAXIMUM_UNAUTHORIZED_RETRIES: u32 = 3;
const DEFAULT_RETRY_DELAY_MS: Duration = Duration::from_millis(500 as u64);
pub type MessageStream =
    Pin<Box<dyn Stream<Item = Result<rtsp_types::Message<Body>, ReadError>> + Send>>;

pub type MessageSink = Pin<Box<dyn Sink<rtsp_types::Message<Body>, Error = std::io::Error> + Send>>;
pub type OnReconnect = Arc<dyn Fn(SocketAddr) -> Result<(), ClientError> + Send + Sync>;

pub struct Client {
    pub url: Url,
    pub username: Option<String>,
    pub password: Option<String>,
    rtsp_machine: RtspMachine,
    stream: Option<MessageStream>,
    sink: Option<MessageSink>,
    on_reconnect: Option<OnReconnect>,
}

#[derive(Debug)]
pub enum ClientError {
    UrlParseError((String, String)),
    SocketAcceptError(std::io::Error),
    ConnectError(std::io::Error),
    NoAuthInWwwHeader,
    WwwAuthParseError(WwwAuthParseError),
    SocketError(std::io::Error),
    MessageSocketError(crate::message_socket::ReadError),
    NotRtspResponse,
    WrongStatusCode(rtsp_types::StatusCode),
    UnexpectedCSeq(String),
    UnexpectedStatusCodeResponse(rtsp_types::StatusCode),
    EventError(crate::rtsp_machine::EventError),
    NotARequest,
}

impl From<ClientError> for ClientActionError {
    fn from(err: ClientError) -> Self {
        ClientActionError::ClientError(err)
    }
}

#[derive(Debug)]
pub enum ClientActionError {
    Teardown,
    CSeqMissing,
    /// Connection failed too many times
    RetriesEnded,
    /// Possbile wrong credentials, or bug in authentication library
    UnauthorizedRetriesEnded,
    RtspMachineError(RtspMachineError),
    ClientError(ClientError),
    UrlParseError(String),
    MediaSelectionError(String),
    UnknownError(String),
}

impl std::convert::From<RtspMachineError> for ClientActionError {
    fn from(rtsp_machine_error: RtspMachineError) -> ClientActionError {
        ClientActionError::RtspMachineError(rtsp_machine_error)
    }
}

fn client_parse_cseq<T>(
    message: &rtsp_types::Message<T>,
) -> std::result::Result<i32, ClientActionError> {
    match parse_c_seq(message) {
        Ok(c_seq) => Ok(c_seq),
        Err(_) => Err(ClientActionError::CSeqMissing),
    }
}

#[derive(Debug)]
pub enum ClientCreationError {
    UrlParseError((String, String)),
}

impl Client {
    /// Both username_ and password_ take precedence over the RTSP url username and password in case they exist
    pub fn new(
        url: &str,
        username_: Option<&str>,
        password_: Option<&str>,
        version: Version,
    ) -> Result<Self, ClientCreationError> {
        let mut username: Option<String> = None;
        let mut password: Option<String> = None;

        let mut parsed_url = match Url::parse(url) {
            Ok(url) => url,
            Err(err) => {
                return Err(ClientCreationError::UrlParseError((
                    url.to_string(),
                    format!("{}", err),
                )))
            }
        };

        if !parsed_url.username().is_empty() {
            username = Some(parsed_url.username().to_string());
        }

        match parsed_url.password() {
            Some(password_) => {
                password = Some(password_.to_string());
            }
            None => {}
        }

        if let Some(username_str) = username_ {
            username = Some(username_str.to_string());
        }

        if let Some(password_str) = password_ {
            password = Some(password_str.to_string());
        }

        // Cleans authentication from URL because we use RTSP Authorization with nonces
        let p1 = parsed_url.set_username("");
        let p2 = parsed_url.set_password(None);

        if let Err(_) = p1 {
            return Err(ClientCreationError::UrlParseError((
                url.to_string(),
                format!("{}", "could not erase username of rtsp url"),
            )));
        }
        if let Err(_) = p2 {
            return Err(ClientCreationError::UrlParseError((
                url.to_string(),
                format!("{}", "could not erase password of rtsp url"),
            )));
        }

        let rtsp_machine = RtspMachine::begin(
            version,
            username.clone(),
            password.clone(),
            parsed_url.clone(),
        );

        Ok(Client {
            url: parsed_url,
            username: username,
            password: password,
            rtsp_machine: rtsp_machine,
            stream: None,
            sink: None,
            on_reconnect: None,
        })
    }

    pub fn new_with_stream_sink(
        url: &str,
        username: Option<&str>,
        password: Option<&str>,
        version: Version,
        read: impl tokio::io::AsyncRead + Unpin + Send + 'static,
        write: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
        on_reconnect: OnReconnect,
    ) -> Result<Self, ClientCreationError> {
        let mut client = Client::new(url, username, password, version)?;
        let stream = super::message_socket::async_read(read, super::MAX_MESSAGE_SIZE);
        let sink = super::message_socket::async_write(write);

        let stream: MessageStream = Box::pin(stream);
        let sink: MessageSink = Box::pin(sink);

        client.stream = Some(stream);
        client.sink = Some(sink);
        client.on_reconnect = Some(on_reconnect.clone());
        Ok(client)
    }

    pub fn set_username(&mut self, s: Option<&str>) {
        self.username = s.map_or(None, |x| Some(x.into()));
    }

    pub fn set_password(&mut self, s: Option<&str>) {
        self.password = s.map_or(None, |x| Some(x.into()));
    }

    pub async fn connect(
        &mut self,
        addr: std::net::SocketAddr,
    ) -> std::result::Result<(), ClientError> {
        info!(target: crate::LOG_RTSP, "connecting to {}", addr);
        if let Some(on_reconnect) = self.on_reconnect.as_ref() {
            on_reconnect(addr)
        } else {
            let connection = TcpStream::connect(addr).await;
            match connection {
                Ok(connection) => {
                    let (read, write) = connection.into_split();
                    let stream = super::message_socket::async_read(read, super::MAX_MESSAGE_SIZE);
                    let sink = super::message_socket::async_write(write);
                    let stream: MessageStream = Box::pin(stream);
                    let sink: MessageSink = Box::pin(sink);
                    self.stream = Some(stream);
                    self.sink = Some(sink);
                    Ok(())
                }
                Err(err) => Err(ClientError::SocketAcceptError(err)),
            }
        }
    }

    async fn request_fill(
        client: Arc<Mutex<Client>>,
        request: &rtsp_types::Message<Body>,
    ) -> Result<rtsp_types::Message<Body>, ClientActionError> {
        let mut request = match request {
            rtsp_types::Message::Request(request) => request.clone(),
            _ => return Err(ClientError::NotARequest.into()),
        };
        let mut client = client.lock().await;
        if let Some(_) = client.rtsp_machine.authorization {
            let authorization = client.rtsp_machine.request_fill_authorization(&request)?;
            request.insert_header(rtsp_types::headers::AUTHORIZATION, authorization);
        }
        let request = rtsp_types::Message::Request(request);
        Ok(request)
    }

    /// Sends a request and expects for an answer with the same CSeq, returning it,
    /// except when the answer has Unauthorized status code. Then it deals with it
    /// and retries with the right credentials
    fn send_and_expect<'a, T, R: 'a + Send>(
        client: Arc<Mutex<Client>>,
        request: &'a Message,
        unauthorized_retry: u32,
    ) -> BoxFuture<'a, Result<(Response, R), ClientActionError>>
    where
        RtspMachine: OnEvent<T, R>,
        T: From<Response>,
    {
        async move {
            let expected_cseq = client_parse_cseq(&request)?;

            let connection_reset = |_| -> ClientActionError {
                ClientError::SocketError(ErrorKind::ConnectionReset.into()).into()
            };

            let connection_reset_2 = || -> ClientActionError {
                ClientError::SocketError(ErrorKind::ConnectionReset.into()).into()
            };

            {
                let request = Client::request_fill(client.clone(), request).await?;
                match client.lock().await.sink.as_mut() {
                    Some(sink) => {
                        log_rtsp_message(&request);
                        sink.send(request.clone()).await.map_err(connection_reset)?;
                    }
                    None => return Err(connection_reset_2()),
                }
            }

            //Need to name it `x` to prevent deadlock on match
            let x = client
                .lock()
                .await
                .stream
                .as_mut()
                .ok_or_else(connection_reset_2)?
                .next()
                .await;
            match x {
                Some(Ok(rtsp_types::Message::Response(response))) => {
                    log_rtsp_response(&response);
                    if response.status() == rtsp_types::StatusCode::Unauthorized {
                        info!(
                            target: crate::LOG_RTSP,
                            "Unauthorized response, should fill credentials and resend",
                        );
                        if unauthorized_retry > 0 {
                            let unauthorized_response = UnauthorizedResponse(response.clone());
                            if let Err(event_error) = OnEvent::<
                                UnauthorizedResponse,
                                UnauthorizedResponseMessage,
                            >::on_event(
                                &mut client.lock().await.rtsp_machine,
                                &unauthorized_response,
                            ) {
                                return Err(ClientError::EventError(event_error).into());
                            }
                            let request = Client::request_fill(client.clone(), request).await?;
                            Client::send_and_expect::<T, R>(
                                client.clone(),
                                &request,
                                unauthorized_retry - 1,
                            )
                            .await
                        } else {
                            Err(ClientActionError::UnauthorizedRetriesEnded)
                        }
                    } else if response.status() == rtsp_types::StatusCode::Ok {
                        let response_cseq = client_parse_cseq(&request)?;
                        if response_cseq == expected_cseq {
                            /*
                                Now that we know that our message is indeed a response to that specific request,
                                we can update the state machine.
                                response.clone().into() will convert to the generic T in `send_expect`'s signature
                            */
                            //TODO: verify if I really need to clone response here
                            let r = client
                                .lock()
                                .await
                                .rtsp_machine
                                .on_event(&response.clone().into());
                            match r {
                                Err(event_error) => {
                                    Err(ClientError::EventError(event_error).into())
                                }
                                Ok(machine_result) => return Ok((response, machine_result)),
                            }
                        } else {
                            Err(ClientError::UnexpectedCSeq(response_cseq.to_string()).into())
                        }
                    } else {
                        Err(ClientError::UnexpectedStatusCodeResponse(response.status()).into())
                    }
                }
                None => Err(ClientError::SocketError(ErrorKind::ConnectionReset.into()).into()),
                Some(Err(err)) => Err(ClientError::MessageSocketError(err).into()),
                Some(Ok(rtsp_types::Message::Request(_))) => {
                    Err(ClientError::NotRtspResponse.into())
                }
                Some(Ok(rtsp_types::Message::Data(_))) => Err(ClientError::NotRtspResponse.into()),
            }
        }
        .boxed()
    }

    /// Retries by calling itself again every time a connection problem occurs, up to connection_retry retries
    pub fn connection_retrier<'a, R: 'a + Send>(
        f: fn(
            Arc<Mutex<Self>>,
            &'a Message,
            u32,
        ) -> BoxFuture<'a, Result<(Response, R), ClientActionError>>,
        addr: SocketAddr,
        f_client: Arc<Mutex<Client>>,
        request: &'a Message,
        unauthorized_retry: u32,
        connection_retry: u32,
        delay: Duration,
    ) -> BoxFuture<'a, Result<(Response, R), ClientActionError>> {
        async move {
            match f(f_client.clone(), request, unauthorized_retry).await {
                Ok(r) => Ok(r),
                Err(ClientActionError::ClientError(ClientError::SocketError(err)))
                | Err(ClientActionError::ClientError(ClientError::MessageSocketError(
                    ReadError::Io(err),
                ))) => {
                    info!(
                        target: crate::LOG_RTSP,
                        "Event: connection/socket error:{}. Reconneting to: {}, retries left: {}",
                        err,
                        addr,
                        connection_retry
                    );
                    sleep(delay).await;
                    match f_client.lock().await.connect(addr).await {
                        Ok(_) => info!(target: crate::LOG_RTSP, "connection ok!"),
                        Err(e) => info!(
                            target: crate::LOG_RTSP,
                            "Reconnection attempt error: {:?}", e
                        ),
                    }
                    if connection_retry > 0 {
                        Client::connection_retrier::<R>(
                            f,
                            addr,
                            f_client,
                            request,
                            unauthorized_retry,
                            connection_retry - 1,
                            delay,
                        )
                        .await
                    } else {
                        Err(ClientActionError::RetriesEnded)
                    }
                }
                Err(err) => Err(ClientActionError::UnknownError(
                    format!("{:?}", err).to_string(),
                )),
            }
        }
        .boxed()
    }

    fn send_with_retry<'a, T, R: 'a + Send>(
        client: Arc<Mutex<Client>>,
        request: &'a Message,
        addr: SocketAddr,
    ) -> BoxFuture<'a, Result<(Response, R), ClientActionError>>
    where
        RtspMachine: OnEvent<T, R>,
        T: From<Response>,
    {
        Client::connection_retrier::<R>(
            Self::send_and_expect,
            addr,
            client,
            request,
            DEFAULT_MAXIMUM_UNAUTHORIZED_RETRIES,
            DEFAULT_MAXIMUM_CONNECTION_RETRIES,
            DEFAULT_RETRY_DELAY_MS,
        )
    }

    /// Polls from the stream until an error occurs (no Message::Data struct is received from sink)
    /// Delivers data by calling `f` callback
    async fn poll_data(
        client: Arc<Mutex<Client>>,
        f: Arc<dyn Fn(&Data<Body>) + Send + Sync>,
    ) -> Result<(), ClientActionError> {
        loop {
            let x = client
                .lock()
                .await
                .stream
                .as_mut()
                .ok_or(ClientActionError::UnknownError(
                    "no sink to poll from".into(),
                ))?
                .next()
                .await;
            match x {
                Some(Ok(rtsp_types::Message::Data(ref data))) => f(data),
                Some(Ok(_)) => {
                    return Err(ClientActionError::UnknownError(
                        "request or response while should receive interleaver binary data".into(),
                    ))
                }
                Some(Err(err)) => return Err(ClientActionError::UnknownError(err.to_string())),
                None => {
                    return Err(ClientError::SocketError(ErrorKind::ConnectionReset.into()).into())
                }
            }
        }
    }

    // TODO: make it better and/or add possibility for the user to pass its own
    // video selection algorithm
    /// Video selection algorithm
    fn choose_video<'a>(videos: Vec<&'a Media>) -> Result<&'a Media, ClientActionError> {
        let chosen_video =
            videos
                .first()
                .map(|x| *x)
                .ok_or(ClientActionError::MediaSelectionError(
                    "Could not select video".into(),
                ))?;
        if chosen_video.proto == "RTP/AVP" && chosen_video.fmt == "96" {
            Ok(chosen_video)
        } else {
            Err(ClientActionError::MediaSelectionError(format!(
                "proto: {}, fmt: {}",
                chosen_video.proto, chosen_video.fmt
            )))
        }
    }

    //TODO: why this works? Couldn't find at RFC
    //TODO: make it better and/or add possibility for the user to pass its own
    /// Track selection algorithm
    fn choose_track<'a>(video: &'a Media) -> Result<&'a str, ClientActionError> {
        let attributes = &video.attributes;
        for attribute in attributes.iter() {
            if attribute.attribute == "control" {
                if let Some(value) = &attribute.value {
                    return Ok(value.as_str());
                }
            }
        }
        Err(ClientActionError::MediaSelectionError(format!(
            "could not choose attribute control for video {:?}",
            video
        )))
    }

    pub async fn play(
        client: Arc<Mutex<Client>>,
        addr: SocketAddr,
        f: Arc<dyn Fn(&Data<Body>) + Send + Sync>,
    ) -> Result<(), ClientActionError> {
        info!(target: crate::LOG_RTSP, "Play called for address {}", addr);
        let options_message = client.clone().lock().await.rtsp_machine.options()?;

        //TODO: log options
        let _options = Client::send_with_retry::<OptionsResponse, OptionsResponseMessage>(
            client.clone(),
            &rtsp_types::Message::Request(options_message),
            addr,
        )
        .await?;

        let describe_message = client.clone().lock().await.rtsp_machine.describe()?;
        let (_, describe_sdp) =
            Client::send_with_retry::<DescribeResponse, DescribeResponseMessage>(
                client.clone(),
                &rtsp_types::Message::Request(describe_message),
                addr,
            )
            .await?;

        let medias = describe_sdp.sdp_session.medias;

        let mut video_medias = Vec::<&Media>::new();
        let mut audio_medias = Vec::<&Media>::new();

        for media in medias.iter() {
            if media.media.contains("video") {
                video_medias.push(media);
            }
            if media.media.contains("audio") {
                audio_medias.push(media);
            }
        }

        info!(
            target: crate::LOG_RTSP,
            "Choosing between videos: {:?} videos", video_medias
        );
        let chosen_video = Client::choose_video(video_medias)?;
        info!(target: crate::LOG_RTSP, "chosen video: {:?}", chosen_video);

        let transport = format!("{}/TCP;interleaved={}", chosen_video.proto, "0");
        let chosen_track = Client::choose_track(chosen_video)?;
        info!(target: crate::LOG_RTSP, "chosen track: {:?}", chosen_track);

        let setup_message = client
            .clone()
            .lock()
            .await
            .rtsp_machine
            .setup(transport.as_str(), chosen_track)?;

        Client::send_with_retry::<SetupResponse, SetupResponseMessage>(
            client.clone(),
            &rtsp_types::Message::Request(setup_message),
            addr,
        )
        .await?;

        let play_message = client.clone().lock().await.rtsp_machine.play()?;
        Client::send_with_retry::<PlayResponse, PlayResponseMessage>(
            client.clone(),
            &rtsp_types::Message::Request(play_message),
            addr,
        )
        .await?;

        Client::poll_data(client.clone(), f).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client;
    #[test]
    fn client_url_no_credentials() {
        let rtsp_client = client::Client::new(
            "rtsp://admin:123456@192.168.1.198:10554/tcp/av0_0",
            None,
            None,
            rtsp_types::Version::V1_0,
        )
        .unwrap();
        println!("parsed_url: {}", rtsp_client.url.as_str());
        let url = rtsp_client.url;
        if !url.username().is_empty() {
            panic!("url shouldn't have username after cleanup");
        }
        match url.password() {
            Some(_) => panic!("url shouldn't have password after cleanup"),
            None => {}
        }
    }

    #[test]
    fn argument_credentials_winrs_over_url_credentials() {
        /*
            We check that the usernames passed to Client::new(_, Some(new_username), Some(new_password))
            substitute the username and password of the URL in Client.url.
        */
        let old_username = "old_user";
        let new_username = "new_user";
        let old_password = "old_password";
        let new_password = "new_password";
        let ip = "192.168.1.198";
        let port = 10554;
        let old_url = format!(
            "rtsp://{}:{}@{}:{}/tcp/av0_0",
            old_username, old_password, ip, port
        );
        let rtsp_client = client::Client::new(
            old_url.as_str(),
            Some(new_username),
            Some(new_password),
            rtsp_types::Version::V1_0,
        )
        .unwrap();
        let url = rtsp_types::Url::parse(old_url.as_str());
        let parsed_username = url.as_ref().unwrap().username();
        let parsed_password = url.as_ref().unwrap().password().unwrap();
        println!("url: {}", old_url);
        println!("parsed username: {}", parsed_username);
        println!("parsed password: {}", parsed_password);
        assert_eq!(
            old_username, parsed_username,
            "old_username: {}, parsed_username: {}",
            old_username, parsed_username
        );
        let parsed_new_username = rtsp_client.username.unwrap();
        let parsed_new_password = rtsp_client.password.unwrap();
        println!("new username: {}", parsed_new_username);
        println!("new password: {}", parsed_new_password);
        assert_eq!(
            new_username, parsed_new_username,
            "new_username: {}, parsed_username: {}",
            new_username, parsed_new_username
        );
        assert_eq!(
            new_password, parsed_new_password,
            "new_password: {}, parsed_new_password: {}",
            new_password, parsed_new_password
        );
    }
}
