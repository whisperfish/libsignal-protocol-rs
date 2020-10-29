use std::{
    cmp::{Ord, Ordering},
    fmt::{self, Display},
    ptr,
};

use crate::{
    errors::{Error, FromInternalErrorCode, InternalError},
    keys::PrivateKey,
    raw_ptr::Raw,
    Buffer, Context,
};

/// The public part of an elliptic curve key pair.
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) raw: Raw<sys::ec_public_key>,
}

impl PublicKey {
    /// Deserialize a [`PublicKey`] from the raw key data.
    pub fn decode_point(ctx: &Context, key: &[u8]) -> Result<PublicKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::curve_decode_point(
                &mut raw,
                key.as_ptr(),
                key.len(),
                ctx.raw(),
            )
            .into_result()?;

            Ok(PublicKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    /// Use this public key to check whether a message matches its signature.
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            let result = sys::curve_verify_signature(
                self.raw.as_const_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            );

            if result == 1 {
                Ok(())
            } else if result == 0 {
                Err(Error::InvalidSignature)
            } else if let Some(err) = InternalError::from_error_code(result) {
                Err(err.into())
            } else {
                Err(Error::InternalError(InternalError::Other(result)))
            }
        }
    }

    /// Uses this public key to check the ECDH agreement with a private key
    pub fn calculate_agreement(
        &self,
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>, Error> {
        unsafe {
            let mut shared_data = std::ptr::null_mut();
            let length = sys::curve_calculate_agreement(
                &mut shared_data,
                self.raw.as_const_ptr(),
                private_key.raw.as_const_ptr(),
            ) as usize;
            if length > 0 {
                let mut secret = Vec::with_capacity(length);
                std::ptr::copy_nonoverlapping(
                    shared_data,
                    secret.as_mut_ptr(),
                    length,
                );
                secret.set_len(length);
                libc::free(shared_data as *mut libc::c_void);
                Ok(secret)
            } else {
                Err(Error::SecretsCalculationError)
            }
        }
    }

    /// Get a copy of to the underlying private key data.
    pub fn to_bytes(&self) -> Result<Buffer, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::ec_public_key_serialize(&mut raw, self.raw.as_const_ptr())
                .into_result()?;
            Ok(Buffer::from_raw(raw))
        }
    }

    /// Return this public key as a base64 encoded string.
    pub fn to_base64(&self) -> Result<String, Error> {
        Ok(base64::encode(self.to_bytes()?))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        let cmp = unsafe {
            sys::ec_public_key_compare(
                self.raw.as_const_ptr(),
                other.raw.as_const_ptr(),
            )
        };

        if cmp < 0 {
            Ordering::Less
        } else if cmp > 0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64().map_err(|_| fmt::Error)?)
    }
}

impl_serializable!(PublicKey, ec_public_key_serialize);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "crypto-native", feature = "crypto-openssl"))]
    #[test]
    fn decode_from_binary() {
        cfg_if::cfg_if! {
            if #[cfg(feature = "crypto-native")] {
                type Crypto = crate::crypto::DefaultCrypto;
            } else if #[cfg(feature = "crypto-openssl")] {
                type Crypto = crate::crypto::OpenSSLCrypto;
            } else {
                compile_error!("These tests require one of the crypto features to be enabled");
            }
        }
        let ctx = Context::new(Crypto::default()).unwrap();
        let public = &[
            0x05, 0x1b, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xdf,
            0xff, 0x94, 0x2b, 0xb2, 0xa4, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x78,
            0xca, 0x3f, 0x4d, 0x6d, 0xf8, 0xb8, 0xbf, 0xa2, 0xe4, 0xee, 0x28,
        ];

        let _got = PublicKey::decode_point(&ctx, public).unwrap();
    }
}
