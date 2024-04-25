// Automatically generated rust module for 'crypto.proto' file

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

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Signature {
    pub scheme: String,
    pub value: Vec<u8>,
}

impl<'a> MessageRead<'a> for Signature {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.scheme = r.read_string(bytes)?.to_owned(),
                Ok(18) => msg.value = r.read_bytes(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Signature {
    fn get_size(&self) -> usize {
        0
        + if self.scheme == String::default() { 0 } else { 1 + sizeof_len((&self.scheme).len()) }
        + if self.value.is_empty() { 0 } else { 1 + sizeof_len((&self.value).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.scheme != String::default() { w.write_with_tag(10, |w| w.write_string(&**&self.scheme))?; }
        if !self.value.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.value))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Hash {
    pub algorithm: String,
    pub value: Vec<u8>,
}

impl<'a> MessageRead<'a> for Hash {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.algorithm = r.read_string(bytes)?.to_owned(),
                Ok(18) => msg.value = r.read_bytes(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Hash {
    fn get_size(&self) -> usize {
        0
        + if self.algorithm == String::default() { 0 } else { 1 + sizeof_len((&self.algorithm).len()) }
        + if self.value.is_empty() { 0 } else { 1 + sizeof_len((&self.value).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.algorithm != String::default() { w.write_with_tag(10, |w| w.write_string(&**&self.algorithm))?; }
        if !self.value.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.value))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct EncodingCommitment {
    pub root: Option<crypto::Hash>,
    pub seed: Vec<u8>,
}

impl<'a> MessageRead<'a> for EncodingCommitment {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.root = Some(r.read_message::<crypto::Hash>(bytes)?),
                Ok(18) => msg.seed = r.read_bytes(bytes)?.to_owned(),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for EncodingCommitment {
    fn get_size(&self) -> usize {
        0
        + self.root.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + if self.seed.is_empty() { 0 } else { 1 + sizeof_len((&self.seed).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.root { w.write_with_tag(10, |w| w.write_message(s))?; }
        if !self.seed.is_empty() { w.write_with_tag(18, |w| w.write_bytes(&**&self.seed))?; }
        Ok(())
    }
}

