// Automatically generated rust module for 'connection.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use quick_protobuf::{MessageInfo, MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TlsVersion {
    UNSPECIFIED = 0,
    V1_2 = 1,
    V1_3 = 2,
}

impl Default for TlsVersion {
    fn default() -> Self {
        TlsVersion::UNSPECIFIED
    }
}

impl From<i32> for TlsVersion {
    fn from(i: i32) -> Self {
        match i {
            0 => TlsVersion::UNSPECIFIED,
            1 => TlsVersion::V1_2,
            2 => TlsVersion::V1_3,
            _ => Self::default(),
        }
    }
}

impl<'a> From<&'a str> for TlsVersion {
    fn from(s: &'a str) -> Self {
        match s {
            "UNSPECIFIED" => TlsVersion::UNSPECIFIED,
            "V1_2" => TlsVersion::V1_2,
            "V1_3" => TlsVersion::V1_3,
            _ => Self::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyType {
    UNSPECIFIED = 0,
    SECP256R1 = 1,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::UNSPECIFIED
    }
}

impl From<i32> for KeyType {
    fn from(i: i32) -> Self {
        match i {
            0 => KeyType::UNSPECIFIED,
            1 => KeyType::SECP256R1,
            _ => Self::default(),
        }
    }
}

impl<'a> From<&'a str> for KeyType {
    fn from(s: &'a str) -> Self {
        match s {
            "UNSPECIFIED" => KeyType::UNSPECIFIED,
            "SECP256R1" => KeyType::SECP256R1,
            _ => Self::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    UNSPECIFIED = 0,
    SENT = 1,
    RECEIVED = 2,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::UNSPECIFIED
    }
}

impl From<i32> for Direction {
    fn from(i: i32) -> Self {
        match i {
            0 => Direction::UNSPECIFIED,
            1 => Direction::SENT,
            2 => Direction::RECEIVED,
            _ => Self::default(),
        }
    }
}

impl<'a> From<&'a str> for Direction {
    fn from(s: &'a str) -> Self {
        match s {
            "UNSPECIFIED" => Direction::UNSPECIFIED,
            "SENT" => Direction::SENT,
            "RECEIVED" => Direction::RECEIVED,
            _ => Self::default(),
        }
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ConnectionInfo {
    pub time: u64,
    pub version: connection::TlsVersion,
    pub transcript_length: Option<connection::TranscriptLength>,
}

impl<'a> MessageRead<'a> for ConnectionInfo {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.time = r.read_uint64(bytes)?,
                Ok(16) => msg.version = r.read_enum(bytes)?,
                Ok(26) => msg.transcript_length = Some(r.read_message::<connection::TranscriptLength>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ConnectionInfo {
    fn get_size(&self) -> usize {
        0
        + if self.time == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.time) as u64) }
        + if self.version == connection::TlsVersion::UNSPECIFIED { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + self.transcript_length.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.time != 0u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.time))?; }
        if self.version != connection::TlsVersion::UNSPECIFIED { w.write_with_tag(16, |w| w.write_enum(*&self.version as i32))?; }
        if let Some(ref s) = self.transcript_length { w.write_with_tag(26, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct TranscriptLength {
    pub sent: u32,
    pub received: u32,
}

impl<'a> MessageRead<'a> for TranscriptLength {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.sent = r.read_uint32(bytes)?,
                Ok(16) => msg.received = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for TranscriptLength {
    fn get_size(&self) -> usize {
        0
        + if self.sent == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.sent) as u64) }
        + if self.received == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.received) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.sent != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.sent))?; }
        if self.received != 0u32 { w.write_with_tag(16, |w| w.write_uint32(*&self.received))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct HandshakeData {
    pub data: connection::mod_HandshakeData::OneOfdata,
}

impl<'a> MessageRead<'a> for HandshakeData {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.data = connection::mod_HandshakeData::OneOfdata::v1_2(r.read_message::<connection::HandshakeDataV1_2>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for HandshakeData {
    fn get_size(&self) -> usize {
        0
        + match self.data {
            connection::mod_HandshakeData::OneOfdata::v1_2(ref m) => 1 + sizeof_len((m).get_size()),
            connection::mod_HandshakeData::OneOfdata::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.data {            connection::mod_HandshakeData::OneOfdata::v1_2(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            connection::mod_HandshakeData::OneOfdata::None => {},
    }        Ok(())
    }
}

pub mod mod_HandshakeData {

use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfdata {
    v1_2(connection::HandshakeDataV1_2),
    None,
}

impl Default for OneOfdata {
    fn default() -> Self {
        OneOfdata::None
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct HandshakeDataV1_2 {
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
    pub server_ephemeral_key: Option<connection::ServerEphemKey>,
}

impl<'a> MessageRead<'a> for HandshakeDataV1_2 {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.client_random = r.read_bytes(bytes)?.to_owned(),
                Ok(18) => msg.server_random = r.read_bytes(bytes)?.to_owned(),
                Ok(26) => msg.server_ephemeral_key = Some(r.read_message::<connection::ServerEphemKey>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for HandshakeDataV1_2 {
    fn get_size(&self) -> usize {
        0
        + if self.client_random.is_empty() { 0 } else { 1 + sizeof_len((&self.client_random).len()) }
        + if self.server_random.is_empty() { 0 } else { 1 + sizeof_len((&self.server_random).len()) }
        + self.server_ephemeral_key.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if !self.client_random.is_empty() { w.write_with_tag(10, |w| w.write_bytes(&**&self.client_random))?; }
        if !self.server_random.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.server_random))?; }
        if let Some(ref s) = self.server_ephemeral_key { w.write_with_tag(26, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ServerIdentity {
    pub name: String,
}

impl<'a> MessageRead<'a> for ServerIdentity {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.name = r.read_string(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ServerIdentity {
    fn get_size(&self) -> usize {
        0
        + if self.name == String::default() { 0 } else { 1 + sizeof_len((&self.name).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.name != String::default() { w.write_with_tag(10, |w| w.write_string(&**&self.name))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct CertificateData {
    pub certs: Vec<Vec<u8>>,
    pub sig: Option<crypto::Signature>,
}

impl<'a> MessageRead<'a> for CertificateData {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.certs.push(r.read_bytes(bytes)?.to_owned()),
                Ok(18) => msg.sig = Some(r.read_message::<crypto::Signature>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for CertificateData {
    fn get_size(&self) -> usize {
        0
        + self.certs.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
        + self.sig.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.certs { w.write_with_tag(10, |w| w.write_bytes(&**s))?; }
        if let Some(ref s) = self.sig { w.write_with_tag(18, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ServerEphemKey {
    pub key_type: connection::KeyType,
    pub key: Vec<u8>,
}

impl<'a> MessageRead<'a> for ServerEphemKey {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.key_type = r.read_enum(bytes)?,
                Ok(18) => msg.key = r.read_bytes(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ServerEphemKey {
    fn get_size(&self) -> usize {
        0
        + if self.key_type == connection::KeyType::UNSPECIFIED { 0 } else { 1 + sizeof_varint(*(&self.key_type) as u64) }
        + if self.key.is_empty() { 0 } else { 1 + sizeof_len((&self.key).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.key_type != connection::KeyType::UNSPECIFIED { w.write_with_tag(8, |w| w.write_enum(*&self.key_type as i32))?; }
        if !self.key.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.key))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct SubsequenceIdx {
    pub ranges: Vec<connection::Range>,
    pub direction: connection::Direction,
}

impl<'a> MessageRead<'a> for SubsequenceIdx {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.ranges.push(r.read_message::<connection::Range>(bytes)?),
                Ok(16) => msg.direction = r.read_enum(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for SubsequenceIdx {
    fn get_size(&self) -> usize {
        0
        + self.ranges.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + if self.direction == connection::Direction::UNSPECIFIED { 0 } else { 1 + sizeof_varint(*(&self.direction) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.ranges { w.write_with_tag(10, |w| w.write_message(s))?; }
        if self.direction != connection::Direction::UNSPECIFIED { w.write_with_tag(16, |w| w.write_enum(*&self.direction as i32))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Range {
    pub start: u32,
    pub end: u32,
}

impl<'a> MessageRead<'a> for Range {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.start = r.read_uint32(bytes)?,
                Ok(16) => msg.end = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Range {
    fn get_size(&self) -> usize {
        0
        + if self.start == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.start) as u64) }
        + if self.end == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.end) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.start != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.start))?; }
        if self.end != 0u32 { w.write_with_tag(16, |w| w.write_uint32(*&self.end))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Transcript {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
}

impl<'a> MessageRead<'a> for Transcript {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.sent = r.read_bytes(bytes)?.to_owned(),
                Ok(18) => msg.received = r.read_bytes(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Transcript {
    fn get_size(&self) -> usize {
        0
        + if self.sent.is_empty() { 0 } else { 1 + sizeof_len((&self.sent).len()) }
        + if self.received.is_empty() { 0 } else { 1 + sizeof_len((&self.received).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if !self.sent.is_empty() { w.write_with_tag(10, |w| w.write_bytes(&**&self.sent))?; }
        if !self.received.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.received))?; }
        Ok(())
    }
}

