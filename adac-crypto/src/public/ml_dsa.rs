// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{
    AdacError,
    KeyOptions::{self, *},
};
use der::{AnyRef, Encode};
use hybrid_array::{typenum::U32, Array};
use ml_dsa::{KeyPair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, VerifyingKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, PrivateKeyInfo};
use std::marker::PhantomData;

// TODO: KeyConverter is only needed until ml-dsa supports the updated IETF standard seed encoding.
type B32 = Array<u8, U32>;
pub struct KeyConverter<P: MlDsaParams> {
    /// The seed this signing key was derived from
    seed: B32,
    phantom: PhantomData<P>,
}

impl<P> TryFrom<PrivateKeyInfo<'_>> for KeyConverter<P>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfo<'_>) -> pkcs8::Result<Self> {
        match private_key_info.algorithm {
            alg if alg == P::ALGORITHM_IDENTIFIER => {}
            other => return Err(spki::Error::OidUnknown { oid: other.oid }.into()),
        }

        let os = private_key_info.private_key;
        let os = if os.len() == 34 { &os[2..] } else { os };
        let seed = Array::try_from(os).map_err(|_| pkcs8::Error::KeyMalformed)?;
        Ok(KeyConverter {
            seed,
            phantom: PhantomData::<P>,
        })
    }
}

impl<P> EncodePrivateKey for KeyConverter<P>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        let pkcs8_key = PrivateKeyInfo::new(P::ALGORITHM_IDENTIFIER, &self.seed);
        Ok(der::SecretDocument::encode_msg(&pkcs8_key)?)
    }
}

impl<P> KeyConverter<P>
where
    P: MlDsaParams,
    KeyConverter<P>: DecodePrivateKey + EncodePrivateKey,
    KeyPair<P>: DecodePrivateKey,
    VerifyingKey<P>: EncodePublicKey,
{
    pub fn fix_pkcs8_der(input: &[u8]) -> Result<Vec<u8>, AdacError> {
        let out = KeyConverter::<P>::from_pkcs8_der(input)
            .map_err(|e| {
                AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e))
            })?
            .to_pkcs8_der()
            .map_err(|e| {
                AdacError::Encoding(format!("Error re-encoding ML-DSA key to PKCS#8: {}", e))
            })?
            .as_bytes()
            .to_vec();
        Ok(out)
    }

    pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
        let key = KeyConverter::<P>::fix_pkcs8_der(key.as_slice())?;
        let evk = KeyPair::<P>::from_pkcs8_der(key.as_slice())
            .map_err(|e| {
                AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e))
            })?
            .verifying_key()
            .encode();
        Ok(evk.to_vec())
    }
}

pub fn from_adac_mldsa<P>(adac: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AdacError>
where
    P: MlDsaParams,
    VerifyingKey<P>: DecodePublicKey,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    let vk_bytes = ml_dsa::EncodedVerifyingKey::<P>::try_from(adac)
        .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&vk_bytes);
    let spki = vk
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding public key: {}", e)))?
        .to_vec();
    Ok((spki, P::ALGORITHM_IDENTIFIER.to_der().unwrap()))
}

pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let (spki, oid) = match key_type {
        MlDsa44Sha256 => from_adac_mldsa::<MlDsa44>(adac)?,
        MlDsa65Sha384 => from_adac_mldsa::<MlDsa65>(adac)?,
        MlDsa87Sha512 => from_adac_mldsa::<MlDsa87>(adac)?,
        _ => return Err(AdacError::InconsistentCrypto),
    };
    let adac = adac.to_vec();

    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid,
        curve: None,
    })
}

pub fn from_spki_mldsa<P>(public_key: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), AdacError>
where
    P: MlDsaParams,
    VerifyingKey<P>: DecodePublicKey,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    let k = VerifyingKey::<P>::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ML-DSA key from SPKI: {}", e)))?
        .encode()
        .as_slice()
        .to_vec();

    Ok((k, P::ALGORITHM_IDENTIFIER.to_der().unwrap()))
}

pub fn from_spki(key_type: KeyOptions, spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let spki = spki.to_vec();
    let (adac, oid) = match key_type {
        MlDsa44Sha256 => from_spki_mldsa::<MlDsa44>(&spki)?,
        MlDsa65Sha384 => from_spki_mldsa::<MlDsa65>(&spki)?,
        MlDsa87Sha512 => from_spki_mldsa::<MlDsa87>(&spki)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid,
        curve: None,
    })
}

pub fn spki_from_pkcs8<P>(key: &Vec<u8>) -> Result<Vec<u8>, AdacError>
where
    P: MlDsaParams,
    KeyConverter<P>: DecodePrivateKey + EncodePrivateKey,
    KeyPair<P>: DecodePrivateKey,
    VerifyingKey<P>: EncodePublicKey,
{
    let key = KeyConverter::<P>::fix_pkcs8_der(key.as_slice())?;
    let spki = KeyPair::<P>::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e)))?
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
        .to_vec();
    Ok(spki)
}
