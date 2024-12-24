// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{AdacError, KeyOptions};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AdacKeyFormat {
    Pkcs8,
    KeyId,
}

pub trait AdacCryptoProvider {
    fn verify(
        &self,
        key_type: KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AdacError>;

    fn hash(&self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError>;

    fn sign(&mut self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError>;

    fn load_key(
        &mut self,
        key_type: KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, AdacError>;
}

pub trait CertificateContent {
    fn get_header(&self) -> &[u8];
    fn get_pubkey(&self) -> &[u8];
    fn get_extension_hash(&self) -> &[u8];
    fn get_signature(&self) -> &[u8];
    fn get_extension(&self) -> &[u8];
}
