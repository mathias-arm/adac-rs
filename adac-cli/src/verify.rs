// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput};
use adac::{CertificateRole, CertificateUsage};
use adac_crypto::public::AdacPublicKey;
use adac_crypto::utils::load_certificates;
use serde::Serialize;
use sha2::Digest;
use sha2::digest::Update;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    certificates: Vec<CertificateVerification>,
    summary: Vec<String>,
    error_count: u64,
}

impl VerificationReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for (i, crt) in self.certificates.iter().enumerate() {
            writeln!(out, "Certificate {}: Key ID {}", i, crt.key_id)?;
            for e in &crt.errors {
                writeln!(out, "Error at level {}: {}", i, e)?;
            }
        }
        for s in &self.summary {
            writeln!(out, "{}", s)?;
        }
        if self.error_count > 0 {
            writeln!(out)?;
            writeln!(
                out,
                "{} error(s) found during verification",
                self.error_count
            )?;
        }

        Ok(())
    }

    pub fn error_code(&self) -> i32 {
        if self.error_count > 0 { 1 } else { 0 }
    }
}

#[derive(Debug, Serialize)]
pub struct CertificateVerification {
    key_id: String,
    errors: Vec<String>,
}

pub fn verify_command(path: &PathBuf) -> anyhow::Result<CommandOutput, CommandError> {
    let chain = load_certificates(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error load certificate chain: {:?}", e),
    })?;

    if chain.is_empty() {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Empty certificate chain"),
        });
    }

    let mut error_count = 0;
    let crypto = adac_crypto_rust::RustCryptoProvider::default();
    let mut pubkey = chain[0].get_public_key();
    let mut header = chain[0].header();
    let mut usage = header.usage;
    let mut soc_id = header.soc_id;
    let mut soc_class = header.soc_class;
    let mut permissions = header.permissions_mask;

    let mut certificates = vec![];

    for i in 0..chain.len() {
        let mut errors = vec![];
        let current = &chain[i];
        header = current.header();

        let public_key = AdacPublicKey::from_adac(header.key_type, current.get_public_key())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing public key at level {}: {:?}", i, e),
            })?;
        let key_id = sha2::Sha256::new().chain(public_key.get_spki()).finalize();
        let key_id = base16ct::lower::encode_string(key_id.as_slice());

        if i == 0 && header.role != CertificateRole::AdacCrtRoleRoot {
            error_count += 1;
            errors.push("First certificate does not have Root role".to_string());
        } else if header.role == CertificateRole::AdacCrtRoleRoot && i > 0 {
            error_count += 1;
            errors.push("Only first certificate can have root role".to_string());
        } else if header.role == CertificateRole::AdacCrtRoleLeaf && i != chain.len() - 1 {
            error_count += 1;
            errors.push("Only last certificate can have leaf role".to_string());
        } else {
            // if i == chain.len() - 1 && header.role != CertificateRole::AdacCrtRoleLeaf {
            //     println!("Note: Last certificate is not Leaf");
            // }
        }

        if usage == CertificateUsage::AdacUsageNeutral {
            usage = header.usage;
        } else if usage != header.usage {
            error_count += 1;
            errors.push(format!(
                "Usage mismatch was {:?} now {:?}",
                usage, header.usage
            ));
        }

        if soc_id == [0x0u8; 16] {
            soc_id = header.soc_id;
        } else if soc_id != header.soc_id {
            error_count += 1;
            errors.push(format!(
                "SoC ID does not match ({:?} != {:?})",
                soc_id, header.soc_id
            ));
        }
        if soc_class == 0 {
            soc_class = header.soc_class;
        } else if header.soc_class != 0 && soc_class != header.soc_class {
            let h_soc_class = header.soc_class;
            error_count += 1;
            errors.push(format!(
                "SoC ID Class not match (0x{:x} != 0x{:x})",
                soc_class, h_soc_class
            ));
        }
        for (i, p) in permissions.iter_mut().enumerate() {
            *p &= header.permissions_mask[i];
        }

        match current.verify(pubkey, &crypto) {
            Ok(()) => {}
            Err(e) => {
                error_count += 1;
                errors.push(format!("Signature verification failed: {:?}", e));
            }
        }
        pubkey = current.get_public_key();

        certificates.push(CertificateVerification { key_id, errors });
    }

    let mut summary = vec![];
    if soc_id != [0x0u8; 16] {
        let mut id = [0x0u8; 16];
        id.copy_from_slice(u128::from_le_bytes(soc_id).to_be_bytes().as_ref());
        summary.push(format!(
            "Restricted to SoC ID: 0x{} ({})",
            base16ct::lower::encode_string(id.as_slice()),
            base16ct::lower::encode_string(soc_id.as_slice())
        ));
    }
    if soc_class != 0x0 {
        summary.push(format!("Restricted to SoC Class: 0x{:x}", soc_class));
    }

    if usage != CertificateUsage::AdacUsageNeutral {
        summary.push(format!("Restricted to usage {:?}", usage));
    }

    let mut effective = [0x00u8; 16];
    effective.copy_from_slice(u128::from_le_bytes(permissions).to_be_bytes().as_ref());
    summary.push(format!(
        "Effective permissions: 0x{} ({})",
        base16ct::lower::encode_string(effective.as_slice()),
        base16ct::lower::encode_string(permissions.as_slice())
    ));
    Ok(CommandOutput::Verify(VerificationReport {
        certificates,
        summary,
        error_count,
    }))
}
