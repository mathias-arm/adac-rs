// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{AdacError, KeyOptions::Ed448Shake256};
use der::{Decode, SliceReader};
use ed448::pkcs8::DecodePrivateKey;
use spki::{DecodePublicKey, EncodePublicKey};

pub fn from_adac(adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut raw = [0u8; ed448::COMPONENT_SIZE];
    raw.copy_from_slice(&adac[..ed448::COMPONENT_SIZE]);
    let pub_key = ed448_goldilocks_plus::PublicKeyBytes(raw);
    let spki = pub_key
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding public key: {}", e)))?
        .to_vec();

    Ok(AdacPublicKey {
        key_type: Ed448Shake256,
        spki,
        adac: adac.to_vec(),
        oid: ed448_goldilocks_plus::ALGORITHM_OID.as_bytes().to_vec(),
        curve: None,
    })
}

pub fn from_spki(spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut sr = SliceReader::new(spki)
        .map_err(|e| AdacError::Encoding(format!("Internal Error: {}", e)))?;
    let pki = spki::SubjectPublicKeyInfo::decode(&mut sr)
        .map_err(|e| AdacError::Encoding(format!("Decoding SPKI for Elliptic Curve: {}", e)))?;
    let mut adac = ed448_goldilocks_plus::VerifyingKey::try_from(pki)
        .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?
        .to_bytes()
        .to_vec();
    adac.append(&mut vec![0u8; 3]);

    Ok(AdacPublicKey {
        key_type: Ed448Shake256,
        spki: spki.to_vec(),
        adac,
        oid: ed448_goldilocks_plus::ALGORITHM_OID.as_bytes().to_vec(),
        curve: None,
    })
}

pub fn spki_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed448::KeypairBytes::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;
    if let Some(pub_key) = k.public_key {
        let pub_key = pub_key.to_bytes();
        let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(&pub_key)
            .map_err(|e| AdacError::Encoding(e.to_string()))?;
        let k = vk
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
            .to_vec();
        Ok(k)
    } else {
        Err(AdacError::InconsistentCrypto)
    }
}

pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed448::KeypairBytes::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;
    if let Some(pub_key) = k.public_key {
        let pub_key = pub_key.to_bytes();
        let mut pk = pub_key.to_vec();
        pk.extend_from_slice(&[0u8; 3]);
        Ok(pk)
    } else {
        Err(AdacError::InconsistentCrypto)
    }
}

pub fn get_adac_from_spki(public_key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed448_goldilocks_plus::VerifyingKey::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from SPKI: {}", e)))?
        .to_bytes()
        .to_vec();
    Ok(k)
}

pub fn get_spki_from_ec_point(point: &[u8]) -> Result<Vec<u8>, AdacError> {
    let p: [u8; 57] = point
        .try_into()
        .map_err(|_| AdacError::InconsistentCrypto)?;
    Ok(from_adac(p.as_slice())?.get_spki().to_vec())
}
