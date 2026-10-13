pub const IDENTIFY: u32 = 0;
pub const SELECT_PROTOCOL: u32 = 1;
pub const READY: u32 = 2;
pub const HEARTBEAT: u32 = 3;
pub const SESSION_DESCRIPTION: u32 = 4;
pub const SPEAKING: u32 = 5;
pub const HEARTBEAT_ACK: u32 = 6;
pub const RESUME: u32 = 7;
pub const HELLO: u32 = 8;
pub const CLIENTS_CONNECT: u32 = 11;
pub const CLIENT_DISCONNECT: u32 = 13;
pub const MEDIA_SINK_WANTS: u32 = 15;
pub const VOICE_BACKEND_VERSION: u32 = 16;
pub const CLIENT_FLAGS: u32 = 18;
pub const PLATFORM: u32 = 20;

pub fn is_sequenced(op: u32) -> bool {
    matches!(
        op,
        SPEAKING | CLIENTS_CONNECT | CLIENT_DISCONNECT | MEDIA_SINK_WANTS | CLIENT_FLAGS | PLATFORM
    )
}
