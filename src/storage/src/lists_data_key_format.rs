//  Copyright (c) 2024-present, arana-db Community.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.

use crate::coding::{decode_fixed, encode_fixed};
use crate::error::Result;
use crate::storage_define::{
    decode_user_key, encode_user_key, ENCODED_KEY_DELIM_SIZE, NEED_TRANSFORM_CHARACTER,
};
use bytes::BytesMut;
use std::mem;

/*
 * 用于 List 数据 key 的格式
 * | reserve1 | key | version | index | reserve2 |
 * |    8B    |     |    8B   |   8B  |   16B    |
 */
pub struct ListsDataKey {
    start: Option<Vec<u8>>,
    space: [u8; 200],
    reserve1: [u8; 8],
    key: Vec<u8>,
    version: u64,
    index: u64,
    reserve2: [u8; 16],
}

impl ListsDataKey {
    pub fn new(key: &[u8], version: u64, index: u64) -> Self {
        Self {
            start: None,
            space: [0; 200],
            reserve1: [0; 8],
            key: key.to_vec(),
            version,
            index,
            reserve2: [0; 16],
        }
    }

    pub fn encode(&mut self) -> Result<&[u8]> {
        let meta_size = self.reserve1.len() + mem::size_of::<u64>() + self.reserve2.len();
        let mut usize = self.key.len() + mem::size_of::<u64>() + ENCODED_KEY_DELIM_SIZE;
        let nzero = self
            .key
            .iter()
            .filter(|&&c| c == NEED_TRANSFORM_CHARACTER as u8)
            .count();
        usize += nzero;
        let needed = meta_size + usize;

        let dst = if needed <= self.space.len() {
            &mut self.space[..needed]
        } else {
            self.start = Some(vec![0; needed]);
            self.start.as_mut().unwrap()
        };

        let mut offset = 0;

        // reserve1: 8 byte
        dst[offset..offset + self.reserve1.len()].copy_from_slice(&self.reserve1);
        offset += self.reserve1.len();

        // encode user key
        let mut temp_buf = BytesMut::new();
        encode_user_key(&self.key, &mut temp_buf)?;
        let encoded_key = temp_buf.as_ref();
        dst[offset..offset + encoded_key.len()].copy_from_slice(encoded_key);
        offset += encoded_key.len();

        // version 8 byte
        let version_slice = &mut dst[offset..offset + mem::size_of::<u64>()];
        encode_fixed(version_slice.as_mut_ptr(), self.version);
        offset += mem::size_of::<u64>();

        // index 8 byte
        let index_slice = &mut dst[offset..offset + mem::size_of::<u64>()];
        encode_fixed(index_slice.as_mut_ptr(), self.index);
        offset += mem::size_of::<u64>();

        // reserve2: 16 byte
        dst[offset..offset + self.reserve2.len()].copy_from_slice(&self.reserve2);

        Ok(if needed <= self.space.len() {
            &self.space[..needed]
        } else {
            self.start.as_ref().unwrap()
        })
    }
}

pub struct ParsedListsDataKey {
    key_str: Vec<u8>,
    reserve1: [u8; 8],
    version: u64,
    index: u64,
    reserve2: [u8; 16],
}

impl ParsedListsDataKey {
    pub fn from_string(key: &str) -> Result<Self> {
        Self::decode(key.as_bytes())
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Self::decode(key)
    }

    pub fn decode(key: &[u8]) -> Result<Self> {
        let mut ptr = 0;
        let mut end_ptr = key.len();

        // 校验长度是否足够
        let min_len = mem::size_of::<[u8; 8]>() + mem::size_of::<[u8; 16]>();
        if key.len() < min_len {
            return Err(crate::error::Error::InvalidFormat {
                message: "Key too short for reserve fields".to_string(),
                location: snafu::location!(),
            });
        }

        // skip head reserve1
        ptr += mem::size_of::<[u8; 8]>();
        // skip tail reserve2
        end_ptr = end_ptr
            .checked_sub(mem::size_of::<[u8; 16]>())
            .ok_or_else(|| crate::error::Error::InvalidFormat {
                message: "Key too short for reserve2".to_string(),
                location: snafu::location!(),
            })?;

        // 查找 encoded_key 的实际长度
        let encoded_key_slice = &key[ptr..end_ptr];
        let mut encoded_key_len = 0;
        while encoded_key_len + ENCODED_KEY_DELIM_SIZE <= encoded_key_slice.len() {
            if &encoded_key_slice[encoded_key_len..encoded_key_len + ENCODED_KEY_DELIM_SIZE]
                == b"\x00\x00"
            {
                encoded_key_len += ENCODED_KEY_DELIM_SIZE;
                break;
            }
            encoded_key_len += 1;
        }

        // 解码 user key
        let mut key_str_buf = BytesMut::new();
        decode_user_key(&encoded_key_slice[..encoded_key_len], &mut key_str_buf)?;
        let key_str = key_str_buf.to_vec();

        ptr += encoded_key_len; // 用实际消耗的字节数推进 ptr

        // version
        let version_slice = &key[ptr..ptr + mem::size_of::<u64>()];
        let version = decode_fixed(version_slice.as_ptr() as *mut u8);
        ptr += mem::size_of::<u64>();

        // index
        let index_slice = &key[ptr..ptr + mem::size_of::<u64>()];
        let index = decode_fixed(index_slice.as_ptr() as *mut u8);
        ptr += mem::size_of::<u64>();

        Ok(Self {
            key_str,
            reserve1: [0; 8],
            version,
            index,
            reserve2: [0; 16],
        })
    }

    pub fn key(&self) -> &[u8] {
        &self.key_str
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn index(&self) -> u64 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_encode_decode() -> Result<()> {
        let key = b"test\x00key";
        let version = 123;
        let index = 456;

        let mut data_key = ListsDataKey::new(key, version, index);
        let encoded = data_key.encode()?;

        let parsed = ParsedListsDataKey::from_slice(encoded)?;

        assert_eq!(parsed.key(), key);
        assert_eq!(parsed.version(), version);
        assert_eq!(parsed.index(), index);
        Ok(())
    }

    #[test]
    fn test_special_characters() -> Result<()> {
        let key = b"special\x00\x01\x00chars";
        let version = 999;
        let index = 888;

        let mut data_key = ListsDataKey::new(key, version, index);
        let encoded = data_key.encode()?;
        let parsed = ParsedListsDataKey::from_slice(encoded)?;

        assert_eq!(parsed.key(), key);
        assert_eq!(parsed.version(), version);
        assert_eq!(parsed.index(), index);
        Ok(())
    }

    #[test]
    fn test_empty_key() -> Result<()> {
        let key = b"";
        let version = 0;
        let index = 0;

        let mut data_key = ListsDataKey::new(key, version, index);
        let encoded = data_key.encode()?;
        let parsed = ParsedListsDataKey::from_slice(encoded)?;

        assert_eq!(parsed.key(), key);
        assert_eq!(parsed.version(), version);
        assert_eq!(parsed.index(), index);
        Ok(())
    }

    #[test]
    fn test_invalid_encoding() {
        let invalid_data = b"invalid\x00\x02data";
        let result = ParsedListsDataKey::from_slice(invalid_data);
        assert!(matches!(result, Err(Error::InvalidFormat { .. })));
    }
}
