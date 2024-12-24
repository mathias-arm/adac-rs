// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::KeyOptions::{
    EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, Ed448Shake256, Ed25519Sha512,
};
use adac::{AdacError, KeyOptions};
use cryptoki::object::KeyType;

pub fn get_ec_key_type(key_type: KeyOptions) -> Result<KeyType, AdacError> {
    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => Ok(KeyType::EC),
        Ed25519Sha512 | Ed448Shake256 => Ok(KeyType::EC_EDWARDS),
        _ => Err(AdacError::InconsistentCrypto),
    }
}
