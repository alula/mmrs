#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CloseCode {
    DecodeError = 4002,
    NotAuthenticated = 4003,
    AuthenticationFailed = 4004,
    AlreadyAuthenticated = 4005,
    SessionNoLongerValid = 4006,
    SessionTimeout = 4009,
    ServerNotFound = 4011,
    UnknownProtocol = 4012,
    Disconnected = 4014,
    ServerCrash = 4015,
    UnknownEncryptionMode = 4016,
    BadRequest = 4020,
}

impl CloseCode {
    pub fn reason(self) -> &'static str {
        match self {
            Self::DecodeError => "Failed to decode payload",
            Self::NotAuthenticated => "Not authenticated",
            Self::AuthenticationFailed => "Authentication failed",
            Self::AlreadyAuthenticated => "Already authenticated",
            Self::SessionNoLongerValid => "Session no longer valid",
            Self::SessionTimeout => "Session timeout",
            Self::ServerNotFound => "Server not found",
            Self::UnknownProtocol => "Unknown protocol",
            Self::Disconnected => "Disconnected",
            Self::ServerCrash => "Voice server crashed",
            Self::UnknownEncryptionMode => "Unknown encryption mode",
            Self::BadRequest => "Bad request",
        }
    }
}
