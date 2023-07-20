//{{ Liquid }}
//Copyright (C) {{ 2015,2016,2017,2018 }}  {{ Blockstream }}

//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU Affero General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU Affero General Public License for more details.

//You should have received a copy of the GNU Affero General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::borrow::Cow;

use elements::opcodes;

use crate::constants;

/// Push a new Vec composed from `header` and `data` bytes onto the given `vec`
pub fn push_commitment(vec: &mut Vec<Vec<u8>>, header: impl AsRef<[u8]>, data: impl AsRef<[u8]>) {
    let (header, data) = (header.as_ref(), data.as_ref());
    let capacity = header.len() + data.len();
    let mut item = Vec::with_capacity(capacity);
    item.extend_from_slice(header);
    item.extend_from_slice(data);
    vec.push(item);
}

/// Convenience function for pushing both descriptors onto the given `vec`
pub fn push_descriptor_commitments<S: ToString>(vec: &mut Vec<Vec<u8>>, bs_descriptor: S, wm_descriptor: S) {
    push_commitment(vec, &constants::BLOCKSIGNER_DESCRIPTOR_HEADER, bs_descriptor.to_string());
    push_commitment(vec, &constants::FEDPEG_DESCRIPTOR_HEADER, wm_descriptor.to_string());
}

/// Extracts the signblock and watchman descriptors as strings from the
/// given `elements::Block`, if they exist.
pub fn extract_descriptor_strings(
    block: &elements::Block,
) -> (Option<Cow<'_, str>>, Option<Cow<'_, str>>) {
    let blks_descriptor_str =
        extract_pushdata_commitment(&block, &constants::BLOCKSIGNER_DESCRIPTOR_HEADER)
            .map(String::from_utf8_lossy);
    let fdpg_descriptor_str =
        extract_pushdata_commitment(&block, &constants::FEDPEG_DESCRIPTOR_HEADER)
            .map(String::from_utf8_lossy);

    (blks_descriptor_str, fdpg_descriptor_str)
}

/// Returns true if the block contains both signblock and watchman descriptor strings.
pub fn contains_descriptor_strings(block: &elements::Block) -> bool {
    if let (Some(_), Some(_)) = extract_descriptor_strings(block) {
        true
    } else {
        false
    }
}

/// Extract the potential slice of bytes after `header` by calling `func` on the coinbase
/// transaction outputs in the given Elements block.
///
/// If multiple outputs include the header, this will return only the **first** occurrence.
///
/// The first argument to `func` is the output's [bitcoin::Script] bytes, while the second is the `header` bytes.
pub fn extract_commitment<'blk, 'hdr, F>(
    block: &'blk elements::Block,
    header: &'hdr [u8],
    func: F,
) -> Option<&'blk [u8]>
where
    F: Fn(&'blk [u8], &'hdr [u8]) -> Option<&'blk [u8]>,
    'hdr: 'blk
{
    if block.txdata.is_empty() || !block.txdata[0].is_coinbase() {
        return None;
    }

    block.txdata[0]
        .output
        .iter()
        .find_map(|o| func(&o.script_pubkey.as_bytes(), header))
}

/// Extracts the OP_PUSHDATA* commitment bytes following `header` bytes from
/// coinbase transactions in `block`
pub fn extract_pushdata_commitment<'blk, 'hdr>(
    block: &'blk elements::Block,
    header: &'hdr [u8],
) -> Option<&'blk [u8]>
where 'hdr: 'blk
{
    extract_commitment(block, header, extract_pushdata)
}

/// Extract the data after `header` in the `script` bytes, if it exists.
fn extract_pushdata<'a>(script: &'a [u8], header: &[u8]) -> Option<&'a [u8]> {
    let len = header.len();
    let min = 1 + 1 + 1 + len; // op_return, pushdata1, len, + header

    if script.len() > min && script[0] == opcodes::all::OP_RETURN.into_u8() {
        let op = opcodes::All::from(script[1]);
        let offset = 2; // script[0] and script[1]
        let header_start = match op {
            opcodes::all::OP_PUSHDATA1 => offset + 1,
            opcodes::all::OP_PUSHDATA2 => offset + 2,
            opcodes::all::OP_PUSHDATA4 => offset + 4,
            _ => return None,
        };
        let data_start = header_start + len;
        if &script[header_start..data_start] == header {
            Some(&script[data_start..])
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use bitcoin::blockdata::opcodes::all::{OP_RETURN, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_PUSHBYTES_6};

    use crate::constants;

    use super::*;

    #[test]
    fn rust_bitwise() {
        // just to make sure the `!` is actually the same as `~`
        let mask: u32 = 0x02;
        assert_eq!(0x03, 0x01 | mask);
        assert_eq!(0x01, 0x03 & !mask);
    }

    #[test]
    fn it_pushes_commitments() {
        let mut vec = Vec::new();
        push_commitment(&mut vec, &[1, 2, 3, 4], &[5, 6, 7, 8]);
        assert_eq!(vec.len(), 1);
        assert_eq!(vec[0].len(), 8);
        assert_eq!(vec[0], vec![1, 2, 3, 4, 5, 6, 7, 8]);

        push_commitment(&mut vec, &[1, 2], &[5, 6]);
        assert_eq!(vec.len(), 2);
        assert_eq!(vec[0].len(), 8);
        assert_eq!(vec[0], vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(vec[1].len(), 4);
        assert_eq!(vec[1], vec![1, 2, 5, 6]);

        let data = &[4, 3, 2, 1];
        let mut expected = constants::FEDPEG_DESCRIPTOR_HEADER.to_vec();
        expected.extend_from_slice(data);
        let mut vec = Vec::new();
        push_commitment(&mut vec, &constants::FEDPEG_DESCRIPTOR_HEADER, &[4, 3, 2, 1]);
        assert_eq!(vec.len(), 1);
        assert_eq!(vec[0].len(), 8);
        assert_eq!(vec[0], expected);
    }

    #[test]
    fn it_extracts_pushdata() {
        // pushdata1
        let haystack = &[OP_RETURN.into_u8(), OP_PUSHDATA1.into_u8(), 0x02, 0x01, 0x02];
        let needle = &[0x01];
        let expected = &[0x02];
        assert_eq!(extract_pushdata(haystack, needle).unwrap(), expected);

        let op_return = OP_RETURN.into_u8();
        let op_pushdata1 = OP_PUSHDATA1.into_u8();
        let op_pushdata2 = OP_PUSHDATA2.into_u8();
        let op_pushdata4 = OP_PUSHDATA4.into_u8();

        // pushdata2
        let haystack = &[op_return, op_pushdata2, 0x01, 0x02, 0x01, 0x02];
        assert_eq!(extract_pushdata(haystack, needle).unwrap(), expected);

        // pushdata4
        let haystack = &[op_return, op_pushdata4, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02];
        assert_eq!(extract_pushdata(haystack, needle).unwrap(), expected);

        // too short
        let haystack = &[op_return, op_pushdata1, 0x02, 0x01];
        assert_eq!(extract_pushdata(haystack, needle), None);

        // not op_return
        let haystack = &[0x6b, op_pushdata4, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02];
        assert_eq!(extract_pushdata(haystack, needle), None);

        // not pushdata opcode
        let haystack = &[op_return, OP_PUSHBYTES_6.into_u8(), 0x01, 0x02, 0x03, 0x04, 0x01, 0x02];
        assert_eq!(extract_pushdata(haystack, needle), None);

        // blocksigner header
        let needle = constants::BLOCKSIGNER_DESCRIPTOR_HEADER;
        let expected = &[0x01, 0x02, 0x03];
        let len = needle.len() + expected.len();
        let mut haystack = vec![op_return, op_pushdata1, len as u8];
        haystack.extend_from_slice(&needle);
        haystack.extend_from_slice(expected);
        assert_eq!(extract_pushdata(&haystack, &needle).unwrap(), expected);

        // fedpeg header
        let needle = constants::FEDPEG_DESCRIPTOR_HEADER;
        let expected = &[0x01, 0x02, 0x03];
        let len = needle.len() + expected.len();
        let mut haystack = vec![op_return, op_pushdata1, len as u8];
        haystack.extend_from_slice(&needle);
        haystack.extend_from_slice(expected);
        assert_eq!(extract_pushdata(&haystack, &needle).unwrap(), expected);
    }
}
