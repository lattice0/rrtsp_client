use crate::body::Body;
use crate::parser_utilities::{parse_c_seq, parse_session};
#[cfg(test)]
use crate::{error, info, warn}; // Workaround to use prinltn! for logs.
#[cfg(not(test))]
use log::{error, info, warn}; // Use log crate when building application
                              //use rand::Rng;
pub use rtsp_types::Url;
use std::collections::HashMap;
//use std::str::FromStr;
pub use rtsp_types::Data;
pub use sdp_types::Media;
use std::str::FromStr;
use www_authenticate::{
    Algorithm, BasicChallengeResponse, DigestChallenge, DigestChallengeResponse, Qop,
    WwwAuthenticate,
};
//RRTSP Client = Rust RTSP Client
const USER_AGENT: &str = "RRTSP Client";

pub type Response = rtsp_types::Response<Body>;
pub type Request = rtsp_types::Request<Body>;
pub type Message = rtsp_types::Message<Body>;

macro_rules! declare_event {
    //TODO: make From return reference
    ($a:ident) => {
        pub(crate) struct $a(pub Response);
        impl From<Response> for $a {
            fn from(response: Response) -> Self {
                $a(response)
            }
        }
    };
}

declare_event!(PlayResponse);
declare_event!(OptionsResponse);
declare_event!(DescribeResponse);
declare_event!(SetupResponse);
declare_event!(PauseResponse);
declare_event!(TeardownResponse);
declare_event!(RecordResponse);
declare_event!(UnauthorizedResponse);

pub struct PlayResponseMessage {}
pub struct OptionsResponseMessage {}
pub struct DescribeResponseMessage {
    pub(crate) sdp_session: sdp_types::Session,
}
pub struct SetupResponseMessage {}
pub struct PauseResponseMessage {}
pub struct TeardownResponseMessage {}
pub struct RecordResponseMessage {}
pub struct UnauthorizedResponseMessage {}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub(crate) enum RtspState {
    Init,
    Ready,
    Playing,
    Recording,
}

#[derive(Debug, Clone)]
pub enum RtspMachineError {
    WwwAuthenticationError(String),
    MissingUsername,
    MissingPassword,
    UTF8ConversionError(String),
}

#[derive(Debug, Clone)]
pub(crate) struct RtspMachine {
    //RTSP internal states according to RFC2326
    pub(crate) state: RtspState,
    pub(crate) session: Option<String>,
    pub(crate) version: rtsp_types::Version,
    pub(crate) c_seq: i32,
    //pub(crate) medias: Option<Vec<sdp_types::Media>>,
    pub(crate) authorization: Option<WwwAuthenticate>,
    //Since Basic challenges have no state, we only store the digest
    pub(crate) digest_challenge_response: Option<www_authenticate::DigestChallengeResponse>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) uuid: Option<String>,
    pub(crate) nounce_count: i32,
    pub(crate) url: Url,
}

impl RtspMachine {
    pub fn new(
        state: RtspState,
        version: rtsp_types::Version,
        username: Option<String>,
        password: Option<String>,
        url: Url,
    ) -> Self {
        //let rng = rand::thread_rng();
        RtspMachine {
            state: state,
            session: None,
            version: version,
            //TODO: i32::MAX+1?
            //c_seq: rng.gen_range(0..i32::MAX),
            c_seq: 1,
            //medias: None,
            //At some RTSP event, it chooses the authorization scheme and places here
            authorization: None,
            digest_challenge_response: None,
            username: username,
            password: password,
            uuid: None,
            nounce_count: 1,
            url: url,
        }
    }

    fn get_username(&self) -> std::result::Result<String, RtspMachineError> {
        match &self.username {
            Some(username) => Ok(username.clone()),
            None => Err(RtspMachineError::MissingUsername),
        }
    }

    fn get_cnounce(&self) -> String {
        "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_string()
    }

    pub fn fresh_cseq(&mut self) -> i32 {
        self.c_seq += 1;
        self.c_seq
    }

    pub fn fresh_nounce_count(&mut self) -> i32 {
        self.nounce_count += 1;
        self.nounce_count
    }

    pub fn request_fill_authorization(
        &mut self,
        request: &rtsp_types::Request<Body>,
    ) -> std::result::Result<String, RtspMachineError> {
        let authorization = self.authorization.as_ref().ok_or_else(|| {
            RtspMachineError::WwwAuthenticationError(
                "request_fill_authorization called but no authorization".to_string(),
            )
        })?;
        if let Some(digest_challenges) = authorization.get::<DigestChallenge>() {
            //let mut challenge_responses = Vec::<String>::new();
            let mut algorithms: HashMap<&Algorithm, &DigestChallenge> = HashMap::new();
            let mut chosen_algorithm = Algorithm::Md5;
            for digest_challenge in digest_challenges.iter() {
                if let Some(algorithm) = &digest_challenge.algorithm {
                    info!(
                        target: crate::LOG_RTSP,
                        "inserting algorithm: {:?}", digest_challenge.algorithm
                    );
                    algorithms.insert(algorithm, digest_challenge);
                } else {
                    algorithms.insert(&Algorithm::Md5, digest_challenge);
                }
            }
            for algorithm in algorithms.iter() {
                match algorithm {
                    (Algorithm::Sha256Sess, _) => chosen_algorithm = Algorithm::Sha256Sess,
                    (Algorithm::Sha256, _) => chosen_algorithm = Algorithm::Sha256,
                    (Algorithm::Sha512Trunc256Sess, _) => {
                        chosen_algorithm = Algorithm::Sha512Trunc256Sess
                    }
                    (Algorithm::Sha512Trunc256, _) => chosen_algorithm = Algorithm::Sha512Trunc256,
                    (Algorithm::Md5, _) => chosen_algorithm = Algorithm::Md5,
                    (Algorithm::Md5Sess, _) => chosen_algorithm = Algorithm::Md5Sess,
                    _ => {
                        warn!(target: crate::LOG_RTSP, "algorithm: {:?} is available on the server but not supported on client", algorithm);
                    }
                }
            }

            let digest_challenge = algorithms.get(&chosen_algorithm).ok_or(
                RtspMachineError::WwwAuthenticationError(
                    "shouldn't arrive here: no chosen digest algorithm".to_string(),
                ),
            )?;
            info!(
                target: crate::LOG_RTSP,
                "filling digest challenge for realm: {}",
                digest_challenge
                    .realm
                    .as_ref()
                    .unwrap_or(&"NO REALM".to_string())
            );
            let chosen_qop: Option<Qop>; // = None;
            if let Some(qops) = &digest_challenge.qop {
                if qops.contains(&Qop::AuthInt) {
                    chosen_qop = Some(Qop::AuthInt);
                } else if qops.contains(&Qop::Auth) {
                    chosen_qop = Some(Qop::Auth);
                } else {
                    chosen_qop = Some(Qop::Auth);
                }
            } else {
                chosen_qop = None;
            }
            info!(target: crate::LOG_RTSP, "chosen_qop: {:?}", chosen_qop);
            let nounce = match &digest_challenge.nonce {
                Some(nounce) => nounce,
                None => {
                    return Err(RtspMachineError::WwwAuthenticationError(
                        "missing nonce".to_string(),
                    ))
                }
            };
            let userhash = Some(false);
            let response_algorithm = match &digest_challenge.algorithm {
                Some(algorithm) => Some(algorithm.clone()),
                None => Some(Algorithm::Md5),
            };
            //TODO: fix all None here, urgent
            let mut digest_challenge_response = DigestChallengeResponse {
                username: self.get_username()?,
                realm: digest_challenge.realm.clone(),
                uri: self.url.path().into(),
                nounce_count: Some(self.fresh_nounce_count()),
                cnounce: Some(self.get_cnounce()),
                nounce: nounce.clone(),
                opaque: digest_challenge.opaque.clone(),
                stale: digest_challenge.stale,
                algorithm: response_algorithm,
                qop: chosen_qop,
                userhash: userhash,
                response: None,
            };

            if self.username.is_some() && self.password.is_some() {
                let s: &str = request.method().into();
                www_authenticate::digest::digest_response(
                    //Some(format!("{:?}", request.method())),
                    Some(s.to_string()),
                    self.password.clone().unwrap(),
                    &mut digest_challenge_response,
                    request.body(),
                )
                .map_err(|err| {
                    RtspMachineError::WwwAuthenticationError(format!(
                        "error in digest_response: {:?}",
                        err
                    ))
                })?;
                let mut buffer = Vec::<u8>::new();
                digest_challenge_response
                    .serialize(&mut buffer)
                    .map_err(|x| RtspMachineError::UTF8ConversionError(format!("{:?}", x)))?;
                let digest_challenge_response = String::from_utf8_lossy(buffer.as_slice());
                //challenge_responses.push(digest_challenge_response.to_string());
                /*
                request_builder = request_builder.header(
                    rtsp_types::headers::AUTHENTICATION_INFO,
                    digest_challenge_response.to_string(),
                );
                */
                Ok(digest_challenge_response.to_string())
            } else {
                Err(RtspMachineError::WwwAuthenticationError(
                    "digest authentication requested but username and/or password empty"
                        .to_string(),
                ))
            }
        } else if let Some(basic_challenges) =
            authorization.get::<www_authenticate::BasicChallenge>()
        {
            info!(target: crate::LOG_RTSP, "has basic challenge");
            //let mut challenge_responses = Vec::<String>::new();
            let basic_challenge =
                basic_challenges
                    .first()
                    .ok_or(RtspMachineError::WwwAuthenticationError(
                        "shouldn't arrive here: no first basic challenge".to_string(),
                    ))?;
            info!(
                target: crate::LOG_RTSP,
                "filling basic challenge for realm: {}", basic_challenge.realm
            );
            let username = match self.username.as_ref() {
                Some(username) => username.clone(),
                None => return Err(RtspMachineError::MissingUsername),
            };
            let password = match self.password.as_ref() {
                Some(password) => password.clone(),
                None => return Err(RtspMachineError::MissingPassword),
            };
            let basic_challenge_response = BasicChallengeResponse {
                username: username,
                password: password,
            };
            if self.username.is_some() && self.password.is_some() {
                let mut buffer = Vec::<u8>::new();
                basic_challenge_response
                    .serialize(&mut buffer)
                    .map_err(|x| RtspMachineError::UTF8ConversionError(x.to_string()))?;
                let basic_challenge_response = String::from_utf8_lossy(buffer.as_slice());
                //challenge_responses.push(basic_challenge_response.to_string());
                //TODO: can we send multiple authorizations?????????????
                /*
                request_builder = request_builder.header(
                    rtsp_types::headers::AUTHORIZATION,
                    basic_challenge_response.to_string(),
                );
                */
                Ok(basic_challenge_response.to_string())
            } else {
                Err(RtspMachineError::WwwAuthenticationError(
                    "basic authentication requested but username and/or password empty".to_string(),
                ))
            }
        } else {
            Err(RtspMachineError::WwwAuthenticationError(
                "no basic or digest challenge".to_string(),
            ))
        }
    }

    //Always builds with the correct c_seq according to the state machine
    pub fn request_builder(
        &mut self,
        method: rtsp_types::Method,
        version: rtsp_types::Version,
    ) -> std::result::Result<rtsp_types::RequestBuilder, RtspMachineError> {
        let c_seq = self.fresh_cseq();
        let mut request_builder = rtsp_types::Request::builder(method, version)
            .header(rtsp_types::headers::CSEQ, c_seq.to_string())
            .header(rtsp_types::headers::USER_AGENT, USER_AGENT)
            .request_uri(self.url.clone());
        if let Some(session) = self.session.clone() {
            request_builder = request_builder.header(rtsp_types::headers::SESSION, session);
        }
        /*
        if let Some(_) = &self.authorization {
            let authorization = self.request_fill_authorization()?;
            request_builder = request_builder.header(rtsp_types::headers::AUTHORIZATION, authorization);
        }
        */
        /*
        if let Some(authorization) = self.authorization.clone() {
            //request_builder = request_builder.header(rtsp_types::headers::AUTHENTICATION_INFO, session);
        }
        */
        Ok(request_builder)
    }

    pub fn options(&mut self) -> std::result::Result<rtsp_types::Request<Body>, RtspMachineError> {
        let mut request = self
            .request_builder(rtsp_types::Method::Options, self.version)?
            .build(Body::default());
        if let Some(_) = &self.authorization {
            let authorization = self.request_fill_authorization(&request)?;
            request.insert_header(rtsp_types::headers::AUTHORIZATION, authorization);
        }
        Ok(request)
    }

    pub fn describe(&mut self) -> std::result::Result<rtsp_types::Request<Body>, RtspMachineError> {
        let mut request = self
            .request_builder(rtsp_types::Method::Describe, self.version)?
            .header(rtsp_types::headers::ACCEPT, "application/sdp")
            .build(Body::default());
        if let Some(_) = &self.authorization {
            let authorization = self.request_fill_authorization(&request)?;
            request.insert_header(rtsp_types::headers::AUTHORIZATION, authorization);
        }
        Ok(request)
    }

    pub fn setup(
        &mut self,
        transport: &str,
        track_id: &str,
    ) -> std::result::Result<rtsp_types::Request<Body>, RtspMachineError> {
        //TODO: FIX ERROR
        let mut url = self.url.clone();
        url.path_segments_mut()
            .map_err(|_| RtspMachineError::MissingPassword)?
            .push(track_id);
        let mut request = self
            .request_builder(rtsp_types::Method::Setup, self.version)?
            .request_uri(url)
            .build(Body::default());
        if let Some(_) = &self.authorization {
            let authorization = self.request_fill_authorization(&request)?;
            request.insert_header(rtsp_types::headers::AUTHORIZATION, authorization);
        }
        request.insert_header(rtsp_types::headers::TRANSPORT, transport);
        Ok(request)
    }

    pub fn play(&mut self) -> std::result::Result<rtsp_types::Request<Body>, RtspMachineError> {
        let mut request = self
            .request_builder(rtsp_types::Method::Play, self.version)?
            .build(Body::default());
        if let Some(_) = &self.authorization {
            let authorization = self.request_fill_authorization(&request)?;
            request.insert_header(rtsp_types::headers::AUTHORIZATION, authorization);
        }
        Ok(request)
    }
}

pub trait OnEvent<T, R> {
    fn on_event(&mut self, event: &T) -> std::result::Result<R, EventError>;
}

impl OnEvent<OptionsResponse, OptionsResponseMessage> for RtspMachine {
    fn on_event(
        &mut self,
        _event: &OptionsResponse,
    ) -> std::result::Result<OptionsResponseMessage, EventError> {
        Ok(OptionsResponseMessage {})
    }
}

impl OnEvent<PlayResponse, PlayResponseMessage> for RtspMachine {
    fn on_event(
        &mut self,
        event: &PlayResponse,
    ) -> std::result::Result<PlayResponseMessage, EventError> {
        match self.state {
            RtspState::Init => Err(EventError::ImpossibleTransition),
            RtspState::Ready => {
                let message = &event.0; //parse_response(&event.0.message)?;
                let response_status = message.status();
                let response_version = message.version();
                match response_status {
                    rtsp_types::StatusCode::Ok => {
                        if response_version != self.version.clone() {
                            return Err(EventError::DifferentVersion);
                        }
                        let session =
                            parse_session(&rtsp_types::Message::Response(event.0.clone()))?;
                        //let c_seq = parse_c_seq(&event.0.message)?;
                        self.state = RtspState::Playing;
                        //self.c_seq += 1;
                        self.session = Some(session);
                        Ok(PlayResponseMessage {})
                    }
                    _ => Err(EventError::UnexpectedStatusCodeResponse((
                        format!("unexpected status code: {}", response_status).to_string(),
                        response_status,
                    ))),
                }
            }
            RtspState::Playing => Err(EventError::ImpossibleTransition),
            RtspState::Recording => Err(EventError::ImpossibleTransition),
        }
    }
}

impl OnEvent<DescribeResponse, DescribeResponseMessage> for RtspMachine {
    fn on_event(
        &mut self,
        event: &DescribeResponse,
    ) -> std::result::Result<DescribeResponseMessage, EventError> {
        match self.state {
            RtspState::Init => {
                let message = &event.0; //parse_response(&event.0.message)?;
                let response_status = message.status();
                let response_version = message.version();
                match response_status {
                    rtsp_types::StatusCode::Ok => {
                        if response_version != self.version.clone() {
                            return Err(EventError::DifferentVersion);
                        }

                        //let medias: Vec<sdp_types::Media>;
                        let sdp_session = sdp_types::Session::parse(message.body());
                        let sdp_session = match sdp_session {
                            Ok(sdp_session) => sdp_session,
                            Err(sdp_error) => return Err(EventError::SdpParseError(sdp_error)),
                        };

                        self.state = RtspState::Init;
                        let response = DescribeResponseMessage {
                            sdp_session: sdp_session,
                        };
                        Ok(response)
                    }
                    _ => Err(EventError::UnexpectedStatusCodeResponse((
                        format!("unexpected status code: {}", response_status).to_string(),
                        response_status,
                    ))),
                }
            }
            RtspState::Ready => Err(EventError::ImpossibleTransition),
            RtspState::Playing => Err(EventError::ImpossibleTransition),
            RtspState::Recording => Err(EventError::ImpossibleTransition),
        }
    }
}

impl OnEvent<SetupResponse, SetupResponseMessage> for RtspMachine {
    fn on_event(
        &mut self,
        event: &SetupResponse,
    ) -> std::result::Result<SetupResponseMessage, EventError> {
        match self.state {
            RtspState::Init => {
                let message = &event.0; //parse_response(&event.0.message)?;
                let response_status = message.status();
                let response_version = message.version();
                match response_status {
                    rtsp_types::StatusCode::Ok => {
                        if response_version != self.version.clone() {
                            return Err(EventError::DifferentVersion);
                        }
                        let session =
                            parse_session(&rtsp_types::Message::Response(event.0.clone()))?;
                        let _c_seq = parse_c_seq(&rtsp_types::Message::Response(event.0.clone()))?;
                        self.state = RtspState::Ready;
                        self.session = Some(session);
                        //self.c_seq += 1;
                        Ok(SetupResponseMessage {})
                    }
                    _ => Err(EventError::UnexpectedStatusCodeResponse((
                        format!("unexpected status code: {}", response_status).to_string(),
                        response_status,
                    ))),
                }
            }
            RtspState::Ready => Err(EventError::ImpossibleTransition),
            RtspState::Playing => Err(EventError::ImpossibleTransition),
            RtspState::Recording => Err(EventError::ImpossibleTransition),
        }
    }
}

impl OnEvent<UnauthorizedResponse, UnauthorizedResponseMessage> for RtspMachine {
    fn on_event(
        &mut self,
        event: &UnauthorizedResponse,
    ) -> std::result::Result<UnauthorizedResponseMessage, EventError> {
        let message = &event.0; //parse_response(&event.0.message)?;
        let response_status = message.status();
        if response_status != rtsp_types::StatusCode::Unauthorized {
            error!(
                "Unauthorized message has no 404 status code. RTSP Message: {:?}",
                response_status
            );
            let s = format!(
                "Unauthorized message has no 404 status code. Code: {}",
                response_status
            );
            return Err(EventError::UnauthorizedResponseParseError(s));
        }
        match message.header(&rtsp_types::headers::WWW_AUTHENTICATE) {
            Some(header_value) => {
                let authorization = header_value.as_str();
                let mut lines = Vec::<Vec<u8>>::new();
                lines.push(authorization.as_bytes().to_vec());
                let authorization = WwwAuthenticate::from_header(lines);
                match authorization {
                    Ok(authorization) => {
                        let digest_challenge = authorization.get::<DigestChallenge>();
                        if let Some(digest_challenges) = digest_challenge {
                            for digest_challenge in digest_challenges.iter() {
                                if let None = digest_challenge.nonce {
                                    return Err(EventError::WwwAuthParseError(
                                        "missing nonce".to_string(),
                                    ));
                                }
                            }
                        }
                        self.authorization = Some(authorization);
                    }
                    Err(err) => {
                        error!("Unauthorized message has authentication header but WwwAuthenticate fails to parse. RTSP Message: {:?}", message);
                        let s = format!("Unauthorized message has authentication header but WwwAuthenticate fails to parse. Header: {}, Parse error: {:?}", header_value, err);
                        return Err(EventError::UnauthorizedResponseParseError(s));
                    }
                }
            }
            None => {
                error!(
                    "Unauthorized message has no AuthenticationInfo header. RTSP Message: {:?}",
                    message
                );
                return Err(EventError::UnauthorizedResponseParseError(
                    "Unauthorized message has no AuthenticationInfo header".to_string(),
                ));
            }
        }
        //TODO: should I expect a session?
        //let session = parse_session(&rtsp_types::Message::Response(event.0.clone()))?;

        //session: Some(session),
        let new_state = self.state.clone();
        info!(
            "RTSP Machine [uuid: {:?}] transition from {:?} to {:?}",
            self.uuid, self.state, new_state
        );
        self.state = new_state;
        Ok(UnauthorizedResponseMessage {})
    }
}

#[derive(Debug)]
pub enum EventError {
    EventNotImplemented,
    ImpossibleTransition,
    DifferentVersion,
    UnexpectedResponse(String),
    UnexpectedStatusCodeResponse((String, rtsp_types::StatusCode)),
    IncorrectCSeq(Option<String>),
    UnknownError,
    SdpParseError(sdp_types::ParserError),
    SessionParseError(String),
    CSeqParseError(String),
    UnauthorizedResponseParseError(String),
    MessageNotResponse,
    WwwAuthParseError(String),
}

impl RtspMachine {
    pub fn begin(
        version: rtsp_types::Version,
        username: Option<String>,
        password: Option<String>,
        url: Url,
    ) -> RtspMachine {
        //let state = Init{};
        RtspMachine::new(RtspState::Init, version, username, password, url)
    }
}

#[cfg(test)]
mod tests {
    use crate::rtsp_machine::*;

    /*
    fn check_cseq_increase(old_c_seq: i32, rtsp_machine: RtspMachine) {
        //assert_eq!(old_c_seq+1, rtsp_machine_wrapper)
    }
    */

    fn describe_response(describe_response: rtsp_types::Response<Body>) {
        println!("describe_response");
        let ip = "192.168.1.165";
        let port = "10554";
        let address_str = format!("{}:{}", ip, port);
        let url = format!("rtsp://admin:19929394@{}/tcp/av0_0", address_str);
        let mut rtsp_machine = RtspMachine::begin(
            rtsp_types::Version::V1_0,
            None,
            None,
            Url::from_str(url.as_str()).unwrap(),
        );
        let describe_response_event = DescribeResponse(describe_response.clone());
        let describe_response_message = rtsp_machine.on_event(&describe_response_event).unwrap();
        match rtsp_machine.state {
            RtspState::Init => {
                assert_eq!(describe_response_message.sdp_session.medias.len() > 0, true);
                let mut has_video = false;
                let mut has_audio = false;
                let mut has_rtp_avp = false;
                for media in &describe_response_message.sdp_session.medias {
                    if media.media == "audio" {
                        has_audio = true;
                    }
                    if media.media == "video" {
                        has_video = true;
                    }
                    if media.proto == "RTP/AVP" {
                        has_rtp_avp = true;
                    }
                }
                println!("media: {:?}", describe_response_message.sdp_session.medias);
                assert_eq!(has_video, true, "has_video: {}", has_video);
                assert_eq!(has_audio, true, "has_audio: {}", has_audio);
                assert_eq!(has_rtp_avp, true, "has_rtp_avp: {}", has_rtp_avp);

                /*
                let body = describe_response.body();
                let parsed_sdp = sdp_types::Session::parse(body).unwrap();
                for media in parsed_sdp.medias.iter() {
                    println!("proto: {}", media.proto);
                    println!("fmt: {}", media.fmt);
                }
                */
            }
            _ => panic!("wrong state: {:?}", rtsp_machine.state),
        }
    }

    #[test]
    fn describe_response_generated() {
        println!("describe_response_generated");
        let describe_response_message = rtsp_types::Response::builder(rtsp_types::Version::V1_0, rtsp_types::StatusCode::Ok).
        header(rtsp_types::HeaderName::from_static_str("CSeq").unwrap(), "3").
        header(rtsp_types::HeaderName::from_static_str("Transport").unwrap(), "RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001;ssrc=1234ABCD").
        build(Body::from(&b"v=0\r
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r
s=SDP Seminar\r
i=A Seminar on the session description protocol\r
u=http://www.example.com/seminars/sdp.pdf\r
e=j.doe@example.com (Jane Doe)\r
p=+1 617 555-6011\r
c=IN IP4 224.2.17.12/127\r
b=AS:128\r
t=2873397496 2873404696\r
r=7d 1h 0 25h\r
z=2882844526 -1h 2898848070 0\r
k=clear:1234\r
a=recvonly\r
m=audio 49170 RTP/AVP 0\r
m=video 51372/2 RTP/AVP 99\r
a=rtpmap:99 h263-1998/90000\r
a=fingerprint:sha-256 3A:96:6D:57:B2:C2:C7:61:A0:46:3E:1C:97:39:D3:F7:0A:88:A0:B1:EC:03:FB:10:A5:5D:3A:37:AB:DD:02:AA\r
"[..]));
        describe_response(describe_response_message);
    }

    #[test]
    fn describe_response_parsed() {
        println!("describe_response_parsed");
        let describe_response_string = "RTSP/1.0 200 OK\r\n\
CSeq: 2\r\n\
Content-Base: rtsp://example.com/media.mp4\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 460\r\n\
\r\n\
v=0\r
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r
s=SDP Seminar\r
i=A Seminar on the session description protocol\r
u=http://www.example.com/seminars/sdp.pdf\r
e=j.doe@example.com (Jane Doe)\r
p=+1 617 555-6011\r
c=IN IP4 224.2.17.12/127\r
b=AS:128\r
t=2873397496 2873404696\r
r=7d 1h 0 25h\r
z=2882844526 -1h 2898848070 0\r
k=clear:1234\r
a=recvonly\r
m=audio 49170 RTP/AVP 0\r
m=video 51372/2 RTP/AVP 99\r
a=rtpmap:99 h263-1998/90000\r
a=fingerprint:sha-256 3A:96:6D:57:B2:C2:C7:61:A0:46:3E:1C:97:39:D3:F7:0A:88:A0:B1:EC:03:FB:10:A5:5D:3A:37:AB:DD:02:AA\r
";
        let (describe_response_message, _size) =
            rtsp_types::Message::<Body>::parse(describe_response_string)
                .expect("Failed to parse data");
        let describe_response_message = match describe_response_message {
            rtsp_types::Message::Response(response) => response,
            _ => panic!("not a response"),
        };
        describe_response(describe_response_message);
    }

    fn setup_response(setup_response: rtsp_types::Response<Body>, session: String) {
        println!("setup_response");
        let ip = "192.168.1.165";
        let port = "10554";
        let address_str = format!("{}:{}", ip, port);
        let url = format!("rtsp://admin:19929394@{}/tcp/av0_0", address_str);
        let mut rtsp_machine = RtspMachine::begin(
            rtsp_types::Version::V1_0,
            None,
            None,
            Url::from_str(url.as_str()).unwrap(),
        );
        let setup_response_event = SetupResponse(setup_response);
        rtsp_machine.on_event(&setup_response_event).unwrap();
        match rtsp_machine.state {
            RtspState::Ready => {
                if rtsp_machine.session.clone().unwrap() != session {
                    panic!(
                        "session not equal to expected. Session: {}, Expected: {}",
                        rtsp_machine.session.clone().unwrap(),
                        session
                    )
                } else {
                    println!("session: {}", rtsp_machine.session.clone().unwrap());
                }
            }
            _ => panic!("wrong state: {:?}", rtsp_machine.state),
        }
    }

    #[test]
    fn setup_response_generated() {
        println!("setup_response_generated");
        let session_example = "12345678";
        let setup_response_message =
            rtsp_types::Response::builder(rtsp_types::Version::V1_0, rtsp_types::StatusCode::Ok)
                .header(
                    rtsp_types::HeaderName::from_static_str("Session").unwrap(),
                    session_example,
                )
                .header(
                    rtsp_types::HeaderName::from_static_str("CSeq").unwrap(),
                    "3",
                )
                .header(
                    rtsp_types::HeaderName::from_static_str("Transport").unwrap(),
                    "RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001;ssrc=1234ABCD",
                )
                .build(Body::from(&b""[..]));
        setup_response(setup_response_message, session_example.to_string());
    }

    #[test]
    fn setup_response_parsed() {
        println!("setup_response_parsed");
        let session_example = "12345678";
        let setup_response_message = format!(
            "RTSP/1.0 200 OK\r\n\
CSeq: 3\r\n\
Transport: RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001;ssrc=1234ABCD\r\n\
Session: {}\r\n\
\r\n\
",
            session_example
        );
        let (setup_response_message, _size) =
            rtsp_types::Message::parse(setup_response_message.as_str())
                .expect("Failed to parse data");
        let setup_response_message = match setup_response_message {
            rtsp_types::Message::Response(response) => response,
            _ => panic!("not a response"),
        };
        setup_response(setup_response_message, session_example.to_string());
    }

    fn play_response(
        setup_response: rtsp_types::Response<Body>,
        play_response: rtsp_types::Response<Body>,
        session: String,
    ) {
        println!("play_response");
        let ip = "192.168.1.165";
        let port = "10554";
        let address_str = format!("{}:{}", ip, port);
        let url = format!("rtsp://admin:19929394@{}/tcp/av0_0", address_str);
        let mut rtsp_machine = RtspMachine::begin(
            rtsp_types::Version::V1_0,
            None,
            None,
            Url::from_str(url.as_str()).unwrap(),
        );
        let setup_response_event = SetupResponse(setup_response);
        let play_response_event = PlayResponse(play_response);
        rtsp_machine.on_event(&setup_response_event).unwrap();
        match &rtsp_machine.state {
            RtspState::Ready => {
                if rtsp_machine.session.clone().unwrap() != session {
                    panic!(
                        "session not equal to expected. Session: {}, Expected: {}",
                        rtsp_machine.session.clone().unwrap(),
                        session
                    )
                } else {
                    println!("session: {}", rtsp_machine.session.clone().unwrap());
                }
            }
            _ => panic!("Should be ready! Wrong state: {:?}", rtsp_machine.state),
        }
        rtsp_machine.on_event(&play_response_event).unwrap();
        match &rtsp_machine.state {
            RtspState::Playing => {
                if rtsp_machine.session.clone().unwrap() != session {
                    panic!(
                        "session not equal to expected. Session: {}, Expected: {}",
                        rtsp_machine.session.clone().unwrap(),
                        session
                    )
                } else {
                    println!("session: {}", rtsp_machine.session.clone().unwrap());
                }
            }
            _ => panic!("Should be playing! Wrong state: {:?}", rtsp_machine.state),
        }
    }

    #[test]
    fn play_response_generated() {
        println!("play_response_generated");
        let session_example = "12345678";

        let setup_response_message =
            rtsp_types::Response::builder(rtsp_types::Version::V1_0, rtsp_types::StatusCode::Ok)
                .header(
                    rtsp_types::HeaderName::from_static_str("Session").unwrap(),
                    session_example,
                )
                .header(
                    rtsp_types::HeaderName::from_static_str("CSeq").unwrap(),
                    "3",
                )
                .header(
                    rtsp_types::HeaderName::from_static_str("Transport").unwrap(),
                    "RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001;ssrc=1234ABCD",
                )
                .build(Body::from(&b""[..]));

        let play_response_message =
            rtsp_types::Response::builder(rtsp_types::Version::V1_0, rtsp_types::StatusCode::Ok)
                .header(
                    rtsp_types::HeaderName::from_static_str("Session").unwrap(),
                    session_example,
                )
                .header(
                    rtsp_types::HeaderName::from_static_str("CSeq").unwrap(),
                    "4",
                )
                .header(
                    rtsp_types::HeaderName::from_static_str("RTP-Info").unwrap(),
                    "url=rtsp://example.com/media.mp4/streamid=0;seq=9810092;rtptime=3450012",
                )
                .build(Body::from(&b""[..]));
        play_response(
            setup_response_message,
            play_response_message,
            session_example.to_string(),
        );
    }

    #[test]
    fn unauthorized_authentication_parse() {
        //According to example from https://tools.ietf.org/html/rfc2617#page-18
        let unauthorized_response_message = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

        let expected_realm = "testrealm@host.com";
        let expected_nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
        let _expected_qop = "auth";
        let expected_opaque = "5ccc069c403ebaf9f0171e9517f40e41";

        let mut lines = Vec::<Vec<u8>>::new();
        let line = unauthorized_response_message.as_bytes().to_vec();
        lines.push(line);
        let www_authenticate = WwwAuthenticate::from_header(lines).unwrap();
        println!("{:?}", www_authenticate);
        let digest_challenges = www_authenticate
            .get::<www_authenticate::DigestChallenge>()
            .expect("No digest challenge found");
        assert_eq!(
            digest_challenges.len(),
            1,
            "digest_challenges len: {}",
            digest_challenges.len()
        );
        for digest_challenge in digest_challenges.iter() {
            assert_eq!(
                digest_challenge.realm.as_ref().unwrap(),
                expected_realm,
                "realm != expected_realm"
            );
            assert_eq!(
                digest_challenge.nonce.as_ref().unwrap(),
                expected_nonce,
                "nonce != expected_nonce"
            );
            assert_eq!(
                digest_challenge.opaque.as_ref().unwrap(),
                expected_opaque,
                "opaque != expected_opaque"
            );

            match digest_challenge.algorithm {
                None => {
                    //We should assume MD5 when None
                }
                _ => {
                    panic!("unexpected algorithm");
                }
            }
            //assert_eq!(digest_challenge.nonce.as_ref().unwrap(), expected_nonce, "digest_challenge.nonce: {}, expected_nonce: {}", digest_challenge.nonce.as_ref().unwrap(), expected_nonce);
        }
    }

    #[test]
    fn basic_challenge() {
        //According to example from https://tools.ietf.org/html/rfc2617#page-6
        let username = Some("Aladdin".to_string());
        let password = Some("open sesame".to_string());
        let expected_authentication = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
        let ip = "192.168.1.165";
        let port = "10554";
        let address_str = format!("{}:{}", ip, port);
        let url = format!("rtsp://admin:19929394@{}/tcp/av0_0", address_str);
        let mut rtsp_machine = RtspMachine::begin(
            rtsp_types::Version::V1_0,
            username,
            password,
            Url::from_str(url.as_str()).unwrap(),
        );
        let c_seq = rtsp_machine.fresh_cseq();
        let unauthorized_response_message = rtsp_types::Response::builder(
            rtsp_types::Version::V1_0,
            rtsp_types::StatusCode::Unauthorized,
        )
        .header(
            rtsp_types::HeaderName::from_static_str("CSeq").unwrap(),
            c_seq.to_string(),
        )
        .header(
            rtsp_types::HeaderName::from_static_str("WWW-Authenticate").unwrap(),
            "Basic realm=\"WallyWorld\"",
        )
        .build(Body::default());
        let unauthorized_response_message = UnauthorizedResponse(unauthorized_response_message);
        rtsp_machine
            .on_event(&unauthorized_response_message)
            .unwrap();
        if rtsp_machine.state != RtspState::Init {
            panic!(
                "Wrong state after describe response. State: {:?}",
                rtsp_machine.state
            );
        }
        let setup_request_message = rtsp_machine
            .setup("RTP/AVP/TCP;interleaved", "track0")
            .unwrap();
        println!("setup_request_message: {:?}", setup_request_message);
        let authorization_info = setup_request_message
            .header(&rtsp_types::headers::AUTHORIZATION)
            .expect("no AUTHORIZATION on header")
            .as_str();
        assert_eq!(authorization_info, expected_authentication);
    }

    #[test]
    fn nounce_count_increase() {
        let ip = "192.168.1.165";
        let port = "10554";
        let address_str = format!("{}:{}", ip, port);
        let url = format!("rtsp://admin:19929394@{}/tcp/av0_0", address_str);
        let mut rtsp_machine = RtspMachine::begin(
            rtsp_types::Version::V1_0,
            Some("Mufasa".to_string()),
            Some("Circle of life".to_string()),
            Url::from_str(url.as_str()).unwrap(),
        );
        //We simulate an UnauthorizedResponse so we can use digest authentication to test nounce_count increase
        let c_seq = rtsp_machine.fresh_cseq();
        let unauthorized_response_message = rtsp_types::Response::builder(
            rtsp_types::Version::V1_0,
            rtsp_types::StatusCode::Unauthorized,
        )
        .header(
            rtsp_types::HeaderName::from_static_str("CSeq").unwrap(),
            c_seq.to_string(),
        )
        .header(
            rtsp_types::HeaderName::from_static_str("WWW-Authenticate").unwrap(),
            "Digest realm=\"http-auth@example.org\", algorithm=MD5, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", qop=auth, opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
        )
        .build(Body::default());
        let unauthorized_response_message = UnauthorizedResponse(unauthorized_response_message);
        info!("sending unauthorized message to rtsp machine");
        rtsp_machine
            .on_event(&unauthorized_response_message)
            .unwrap();
        if rtsp_machine.state != RtspState::Init {
            panic!(
                "Wrong state after describe response. State: {:?}",
                rtsp_machine.state
            );
        }
        //Now that unauthorized response was acknowledged, we create a request, which should have an increased nounce and etc
        let describe_request = rtsp_machine.describe().unwrap();
        info!("Describe: \n{:?}", describe_request);
        let authentication_info = describe_request
            .header(&rtsp_types::HeaderName::from_static_str("Authorization").unwrap())
            .unwrap();
        //There's no Authentication-Info parser so we just check for the nc on the String
        if !authentication_info.to_string().contains("nc=00000002") {
            panic!(
                "nc increase failure! Authentication-Info: {}",
                authentication_info
            );
        }
    }

    #[test]
    fn setup() {
        let ip = "192.168.1.165";
        let port = "10554";
        let address_str = format!("{}:{}", ip, port);
        let url = format!("rtsp://admin:19929394@{}/tcp/av0_0", address_str);
        let _rtsp_machine = RtspMachine::begin(
            rtsp_types::Version::V1_0,
            None,
            None,
            Url::from_str(url.as_str()).unwrap(),
        );
    }
}
