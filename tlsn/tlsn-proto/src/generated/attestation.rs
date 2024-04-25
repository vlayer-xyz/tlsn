// Automatically generated rust module for 'attestation.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use std::collections::HashMap;
type KVMap<K, V> = HashMap<K, V>;
use quick_protobuf::{MessageInfo, MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct AttestationHeader {
    pub id: Vec<u8>,
    pub version: u32,
    pub root: Option<crypto::Hash>,
}

impl<'a> MessageRead<'a> for AttestationHeader {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.id = r.read_bytes(bytes)?.to_owned(),
                Ok(16) => msg.version = r.read_uint32(bytes)?,
                Ok(26) => msg.root = Some(r.read_message::<crypto::Hash>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for AttestationHeader {
    fn get_size(&self) -> usize {
        0
        + if self.id.is_empty() { 0 } else { 1 + sizeof_len((&self.id).len()) }
        + if self.version == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + self.root.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if !self.id.is_empty() { w.write_with_tag(10, |w| w.write_bytes(&**&self.id))?; }
        if self.version != 0u32 { w.write_with_tag(16, |w| w.write_uint32(*&self.version))?; }
        if let Some(ref s) = self.root { w.write_with_tag(26, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct AttestationBody {
    pub fields: KVMap<u32, attestation::Field>,
}

impl<'a> MessageRead<'a> for AttestationBody {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => {
                    let (key, value) = r.read_map(bytes, |r, bytes| Ok(r.read_uint32(bytes)?), |r, bytes| Ok(r.read_message::<attestation::Field>(bytes)?))?;
                    msg.fields.insert(key, value);
                }
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for AttestationBody {
    fn get_size(&self) -> usize {
        0
        + self.fields.iter().map(|(k, v)| 1 + sizeof_len(2 + sizeof_varint(*(k) as u64) + sizeof_len((v).get_size()))).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for (k, v) in self.fields.iter() { w.write_with_tag(10, |w| w.write_map(2 + sizeof_varint(*(k) as u64) + sizeof_len((v).get_size()), 8, |w| w.write_uint32(*k), 18, |w| w.write_message(v)))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Attestation {
    pub signature: Option<crypto::Signature>,
    pub header: Option<attestation::AttestationHeader>,
    pub body: Option<attestation::AttestationBody>,
}

impl<'a> MessageRead<'a> for Attestation {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.signature = Some(r.read_message::<crypto::Signature>(bytes)?),
                Ok(18) => msg.header = Some(r.read_message::<attestation::AttestationHeader>(bytes)?),
                Ok(26) => msg.body = Some(r.read_message::<attestation::AttestationBody>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Attestation {
    fn get_size(&self) -> usize {
        0
        + self.signature.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.header.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.body.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.signature { w.write_with_tag(10, |w| w.write_message(s))?; }
        if let Some(ref s) = self.header { w.write_with_tag(18, |w| w.write_message(s))?; }
        if let Some(ref s) = self.body { w.write_with_tag(26, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct AttestationFull {
    pub signature: Option<crypto::Signature>,
    pub header: Option<attestation::AttestationHeader>,
    pub body: Option<attestation::AttestationBody>,
    pub transcript: Option<connection::Transcript>,
    pub secrets: Vec<attestation::Secret>,
}

impl<'a> MessageRead<'a> for AttestationFull {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.signature = Some(r.read_message::<crypto::Signature>(bytes)?),
                Ok(18) => msg.header = Some(r.read_message::<attestation::AttestationHeader>(bytes)?),
                Ok(26) => msg.body = Some(r.read_message::<attestation::AttestationBody>(bytes)?),
                Ok(34) => msg.transcript = Some(r.read_message::<connection::Transcript>(bytes)?),
                Ok(42) => msg.secrets.push(r.read_message::<attestation::Secret>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for AttestationFull {
    fn get_size(&self) -> usize {
        0
        + self.signature.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.header.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.body.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.transcript.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.secrets.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.signature { w.write_with_tag(10, |w| w.write_message(s))?; }
        if let Some(ref s) = self.header { w.write_with_tag(18, |w| w.write_message(s))?; }
        if let Some(ref s) = self.body { w.write_with_tag(26, |w| w.write_message(s))?; }
        if let Some(ref s) = self.transcript { w.write_with_tag(34, |w| w.write_message(s))?; }
        for s in &self.secrets { w.write_with_tag(42, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Field {
    pub data: attestation::mod_Field::OneOfdata,
}

impl<'a> MessageRead<'a> for Field {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.data = attestation::mod_Field::OneOfdata::connection_info(r.read_message::<connection::ConnectionInfo>(bytes)?),
                Ok(18) => msg.data = attestation::mod_Field::OneOfdata::handshake_data(r.read_message::<connection::HandshakeData>(bytes)?),
                Ok(26) => msg.data = attestation::mod_Field::OneOfdata::cert_commitment(r.read_message::<crypto::Hash>(bytes)?),
                Ok(34) => msg.data = attestation::mod_Field::OneOfdata::cert_chain_commitment(r.read_message::<crypto::Hash>(bytes)?),
                Ok(42) => msg.data = attestation::mod_Field::OneOfdata::encoding_commitment(r.read_message::<crypto::EncodingCommitment>(bytes)?),
                Ok(50) => msg.data = attestation::mod_Field::OneOfdata::plaintext_hash(r.read_message::<attestation::PlaintextHash>(bytes)?),
                Ok(58) => msg.data = attestation::mod_Field::OneOfdata::extra_data(r.read_bytes(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Field {
    fn get_size(&self) -> usize {
        0
        + match self.data {
            attestation::mod_Field::OneOfdata::connection_info(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Field::OneOfdata::handshake_data(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Field::OneOfdata::cert_commitment(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Field::OneOfdata::cert_chain_commitment(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Field::OneOfdata::encoding_commitment(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Field::OneOfdata::plaintext_hash(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Field::OneOfdata::extra_data(ref m) => 1 + sizeof_len((m).len()),
            attestation::mod_Field::OneOfdata::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.data {            attestation::mod_Field::OneOfdata::connection_info(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            attestation::mod_Field::OneOfdata::handshake_data(ref m) => { w.write_with_tag(18, |w| w.write_message(m))? },
            attestation::mod_Field::OneOfdata::cert_commitment(ref m) => { w.write_with_tag(26, |w| w.write_message(m))? },
            attestation::mod_Field::OneOfdata::cert_chain_commitment(ref m) => { w.write_with_tag(34, |w| w.write_message(m))? },
            attestation::mod_Field::OneOfdata::encoding_commitment(ref m) => { w.write_with_tag(42, |w| w.write_message(m))? },
            attestation::mod_Field::OneOfdata::plaintext_hash(ref m) => { w.write_with_tag(50, |w| w.write_message(m))? },
            attestation::mod_Field::OneOfdata::extra_data(ref m) => { w.write_with_tag(58, |w| w.write_bytes(&**m))? },
            attestation::mod_Field::OneOfdata::None => {},
    }        Ok(())
    }
}

pub mod mod_Field {

use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfdata {
    connection_info(connection::ConnectionInfo),
    handshake_data(connection::HandshakeData),
    cert_commitment(crypto::Hash),
    cert_chain_commitment(crypto::Hash),
    encoding_commitment(crypto::EncodingCommitment),
    plaintext_hash(attestation::PlaintextHash),
    extra_data(Vec<u8>),
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
pub struct Secret {
    pub data: attestation::mod_Secret::OneOfdata,
}

impl<'a> MessageRead<'a> for Secret {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.data = attestation::mod_Secret::OneOfdata::cert_secrets(r.read_message::<attestation::CertificateSecrets>(bytes)?),
                Ok(18) => msg.data = attestation::mod_Secret::OneOfdata::server_identity(r.read_message::<connection::ServerIdentity>(bytes)?),
                Ok(26) => msg.data = attestation::mod_Secret::OneOfdata::plaintext_hash(r.read_message::<attestation::PlaintextHashSecret>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Secret {
    fn get_size(&self) -> usize {
        0
        + match self.data {
            attestation::mod_Secret::OneOfdata::cert_secrets(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Secret::OneOfdata::server_identity(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Secret::OneOfdata::plaintext_hash(ref m) => 1 + sizeof_len((m).get_size()),
            attestation::mod_Secret::OneOfdata::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.data {            attestation::mod_Secret::OneOfdata::cert_secrets(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            attestation::mod_Secret::OneOfdata::server_identity(ref m) => { w.write_with_tag(18, |w| w.write_message(m))? },
            attestation::mod_Secret::OneOfdata::plaintext_hash(ref m) => { w.write_with_tag(26, |w| w.write_message(m))? },
            attestation::mod_Secret::OneOfdata::None => {},
    }        Ok(())
    }
}

pub mod mod_Secret {

use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfdata {
    cert_secrets(attestation::CertificateSecrets),
    server_identity(connection::ServerIdentity),
    plaintext_hash(attestation::PlaintextHashSecret),
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
pub struct CertificateSecrets {
    pub data: Option<connection::CertificateData>,
    pub cert_nonce: Vec<u8>,
    pub cert_chain_nonce: Vec<u8>,
}

impl<'a> MessageRead<'a> for CertificateSecrets {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.data = Some(r.read_message::<connection::CertificateData>(bytes)?),
                Ok(18) => msg.cert_nonce = r.read_bytes(bytes)?.to_owned(),
                Ok(26) => msg.cert_chain_nonce = r.read_bytes(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for CertificateSecrets {
    fn get_size(&self) -> usize {
        0
        + self.data.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + if self.cert_nonce.is_empty() { 0 } else { 1 + sizeof_len((&self.cert_nonce).len()) }
        + if self.cert_chain_nonce.is_empty() { 0 } else { 1 + sizeof_len((&self.cert_chain_nonce).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.data { w.write_with_tag(10, |w| w.write_message(s))?; }
        if !self.cert_nonce.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.cert_nonce))?; }
        if !self.cert_chain_nonce.is_empty() { w.write_with_tag(26, |w| w.write_bytes(&**&self.cert_chain_nonce))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct PlaintextHashSecret {
    pub idx: Option<connection::SubsequenceIdx>,
    pub nonce: Vec<u8>,
    pub commitment_id: u32,
}

impl<'a> MessageRead<'a> for PlaintextHashSecret {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.idx = Some(r.read_message::<connection::SubsequenceIdx>(bytes)?),
                Ok(18) => msg.nonce = r.read_bytes(bytes)?.to_owned(),
                Ok(24) => msg.commitment_id = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for PlaintextHashSecret {
    fn get_size(&self) -> usize {
        0
        + self.idx.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + if self.nonce.is_empty() { 0 } else { 1 + sizeof_len((&self.nonce).len()) }
        + if self.commitment_id == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.commitment_id) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.idx { w.write_with_tag(10, |w| w.write_message(s))?; }
        if !self.nonce.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.nonce))?; }
        if self.commitment_id != 0u32 { w.write_with_tag(24, |w| w.write_uint32(*&self.commitment_id))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct PlaintextHash {
    pub idx: Option<connection::SubsequenceIdx>,
    pub hash: Option<crypto::Hash>,
}

impl<'a> MessageRead<'a> for PlaintextHash {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.idx = Some(r.read_message::<connection::SubsequenceIdx>(bytes)?),
                Ok(18) => msg.hash = Some(r.read_message::<crypto::Hash>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for PlaintextHash {
    fn get_size(&self) -> usize {
        0
        + self.idx.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.hash.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.idx { w.write_with_tag(10, |w| w.write_message(s))?; }
        if let Some(ref s) = self.hash { w.write_with_tag(18, |w| w.write_message(s))?; }
        Ok(())
    }
}

