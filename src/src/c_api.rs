use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::slice;

use crate::messages::DiscoveryRequest;

#[repr(C)]
pub struct AlnpBytes {
    pub data: *mut u8,
    pub len: u32,
}

#[repr(C)]
pub struct AlnpDiscoveryRequest {
    pub client_nonce: AlnpBytes,
    pub requested: *const *const c_char,
    pub requested_len: u32,
}

impl AlnpBytes {
    fn as_mut_slice(&mut self) -> Option<&mut [u8]> {
        if self.data.is_null() {
            return None;
        }
        unsafe { Some(slice::from_raw_parts_mut(self.data, self.len as usize)) }
    }
}

unsafe fn read_bytes(ptr: *const u8, len: u32) -> Result<Vec<u8>, ()> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(());
    }
    let slice = slice::from_raw_parts(ptr, len as usize);
    Ok(slice.to_vec())
}

unsafe fn read_requested(ptr: *const *const c_char, len: u32) -> Result<Vec<String>, ()> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(());
    }
    let mut requested = Vec::with_capacity(len as usize);
    for idx in 0..len as usize {
        let cstr_ptr = *ptr.add(idx);
        if cstr_ptr.is_null() {
            return Err(());
        }
        let cstr = CStr::from_ptr(cstr_ptr);
        requested.push(cstr.to_string_lossy().into_owned());
    }
    Ok(requested)
}

unsafe fn copy_to_buffer(dest: &mut AlnpBytes, bytes: &[u8]) -> Result<(), ()> {
    let capacity = dest.len as usize;
    if bytes.len() > capacity {
        dest.len = bytes.len() as u32;
        return Err(());
    }
    let target = dest
        .as_mut_slice()
        .ok_or(())?
        .get_mut(..bytes.len())
        .ok_or(())?;
    target.copy_from_slice(bytes);
    dest.len = bytes.len() as u32;
    Ok(())
}

#[no_mangle]
pub extern "C" fn alnp_build_discovery_request(
    req: *const AlnpDiscoveryRequest,
    out_buf: *mut AlnpBytes,
) -> c_int {
    let req = match unsafe { req.as_ref() } {
        Some(value) => value,
        None => return -1,
    };
    let out_buf = match unsafe { out_buf.as_mut() } {
        Some(buf) => buf,
        None => return -1,
    };

    let nonce =
        match unsafe { read_bytes(req.client_nonce.data as *const u8, req.client_nonce.len) } {
            Ok(vec) => vec,
            Err(_) => return -1,
        };

    let requested = match unsafe { read_requested(req.requested, req.requested_len) } {
        Ok(list) => list,
        Err(_) => return -1,
    };

    let discovery = DiscoveryRequest::new(requested, nonce);
    let encoded = match serde_cbor::to_vec(&discovery) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    if unsafe { copy_to_buffer(out_buf, &encoded) }.is_err() {
        return -1;
    }
    0
}
