// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput};
use adac_crypto::utils::{load_certificates, save_certificates};
use serde::Serialize;
use sha2::Digest;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct RotReport {
    pub algorithm: String,
    pub hash: String,
}

impl RotReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        writeln!(
            out,
            "Hash ({}) of ADAC public-key: {}",
            self.algorithm, self.hash
        )?;
        Ok(())
    }
}

pub fn rot_command(
    path: &PathBuf,
    hash: &Option<String>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let chain = load_certificates(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;
    if let Some(crt) = chain.first() {
        let pub_key = crt.get_public_key();
        let hash_algo = match hash {
            None => "sha256".to_string(),
            Some(h) => h.to_ascii_lowercase(),
        };
        let hash = match hash_algo.as_str() {
            "sha256" => sha2::Sha256::digest(pub_key).to_vec(),
            "sha384" => sha2::Sha384::digest(pub_key).to_vec(),
            "sha512" => sha2::Sha512::digest(pub_key).to_vec(),
            _ => {
                return Err(CommandError::InvalidParameter {
                    parameter: "--hash".to_string(),
                });
            }
        };

        Ok(CommandOutput::RotHash(RotReport {
            algorithm: hash_algo.clone(),
            hash: base16ct::lower::encode_string(hash.as_slice()),
        }))
    } else {
        Err(CommandError::AdacError {
            source: anyhow::anyhow!("Certificate chain is empty"),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct PopReport {
    pub certificate: String,
    pub path: Option<PathBuf>,
}

impl PopReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.path.is_none() {
            writeln!(out, "{}", self.certificate)?;
        }
        Ok(())
    }
}

pub fn pop_command(
    path: &PathBuf,
    output: &Option<PathBuf>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let mut chain = load_certificates(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;
    if let Some(crt) = chain.pop() {
        chain = vec![crt];
    }

    let certificate = save_certificates(&chain).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error serializing certificates: {:?}", e),
    })?;

    if let Some(path) = output {
        let mut file = std::fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;

        file.write_all(certificate.as_bytes())
            .map_err(|e| CommandError::FileWrite {
                path: path.clone(),
                source: e,
            })?;
    }

    let path = output.clone();
    Ok(CommandOutput::Pop(PopReport { certificate, path }))
}

#[derive(Debug, Serialize)]
pub struct PushReport {
    pub chain: String,
    pub path: Option<PathBuf>,
}

impl PushReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.path.is_none() {
            writeln!(out, "{}", self.chain)?;
        }
        Ok(())
    }
}

pub fn push_command(
    chain: &PathBuf,
    path: &PathBuf,
    output: &Option<PathBuf>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let mut chain = load_certificates(chain).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;

    let mut certificates = load_certificates(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;

    chain.append(&mut certificates);

    let chain = save_certificates(&chain).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error serializing certificates: {:?}", e),
    })?;

    if let Some(path) = output {
        let mut file = std::fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;

        file.write_all(chain.as_bytes())
            .map_err(|e| CommandError::FileWrite {
                path: path.clone(),
                source: e,
            })?;
    }

    let path = output.clone();
    Ok(CommandOutput::Push(PushReport { chain, path }))
}
