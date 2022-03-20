use crate::rtsp_machine::EventError;

pub(crate) fn parse_c_seq<T>(message: &rtsp_types::Message<T>) -> std::result::Result<i32, EventError> {
    let c_seq = match message {
        rtsp_types::Message::Request(request) => request.header(&rtsp_types::HeaderName::from_static_str("CSeq").unwrap()),
        rtsp_types::Message::Response(response) => response.header(&rtsp_types::HeaderName::from_static_str("CSeq").unwrap()),
        rtsp_types::Message::Data(_) => return Err(EventError::CSeqParseError("data message type not covered".to_string()))
    };
    match c_seq {
        Some(c_seq) => {
            let c_seq_string = c_seq.as_str().to_string().parse::<i32>();
            match c_seq_string {
                Ok(c_seq_integer) => Ok(c_seq_integer),
                Err(_) => return Err(EventError::IncorrectCSeq(Some(c_seq.as_str().to_string())))
            }
        },
        None => return Err(EventError::IncorrectCSeq(None))
    }
}

pub(crate) fn parse_session<T>(message: &rtsp_types::Message<T>) -> std::result::Result<String, EventError> {
    let session = match message {
        rtsp_types::Message::Request(request) => request.header(&rtsp_types::HeaderName::from_static_str("Session").unwrap()),
        rtsp_types::Message::Response(response) => response.header(&rtsp_types::HeaderName::from_static_str("Session").unwrap()),
        rtsp_types::Message::Data(_) => return Err(EventError::SessionParseError("data message type not covered".to_string()))
    };
    match session {
        Some(session) => Ok(session.as_str().to_string()),
        None => return Err(EventError::UnexpectedResponse("no session in response with Ok(200) status".to_string()))
    }
}

/*
pub(crate) fn parse_response<T>(message: &rtsp_types::Message<T>) -> std::result::Result<&rtsp_types::Response<T>, EventError> {
    match message {
        rtsp_types::Message::Response(message) => Ok(message),
        _ => return Err(EventError::MessageNotResponse)
    }
}
*/