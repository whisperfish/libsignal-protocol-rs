use std::convert::TryFrom;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[allow(missing_docs)]
pub enum InternalError {
    #[error("No Memory")]
    NoMemory,
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Unknown error")]
    Unknown,
    #[error("Duplicate message")]
    DuplicateMessage,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid key ID")]
    InvalidKeyId,
    #[error("Invalid MAC")]
    InvalidMAC,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Legacy message")]
    LegacyMessage,
    #[error("No session")]
    NoSession,
    #[error("Stale key exchange")]
    StaleKeyExchange,
    #[error("Untrusted identity")]
    UntrustedIdentity,
    #[error("Varifying signature failed")]
    VerifySignatureVerificationFailed,
    #[error("Invalid protobuf")]
    InvalidProtoBuf,
    #[error("FP version mismatched")]
    FPVersionMismatch,
    #[error("FP ident mismatched")]
    FPIdentMismatch,
    #[error("Unknown error {0}")]
    Other(i32),
    #[error("Unknown ciphertext type {0}")]
    UnknownCiphertextType(u32),
    #[error("Cannot serialize")]
    SerializationError,
}

impl InternalError {
    /// Try to figure out what type of error a code corresponds to.
    pub fn from_error_code(code: i32) -> Option<InternalError> {
        match code {
            sys::SG_ERR_NOMEM => Some(InternalError::NoMemory),
            sys::SG_ERR_INVAL => Some(InternalError::InvalidArgument),
            sys::SG_ERR_UNKNOWN => Some(InternalError::Unknown),
            sys::SG_ERR_DUPLICATE_MESSAGE => {
                Some(InternalError::DuplicateMessage)
            },
            sys::SG_ERR_INVALID_KEY => Some(InternalError::InvalidKey),
            sys::SG_ERR_INVALID_KEY_ID => Some(InternalError::InvalidKeyId),
            sys::SG_ERR_INVALID_MAC => Some(InternalError::InvalidMAC),
            sys::SG_ERR_INVALID_MESSAGE => Some(InternalError::InvalidMessage),
            sys::SG_ERR_INVALID_VERSION => Some(InternalError::InvalidVersion),
            sys::SG_ERR_LEGACY_MESSAGE => Some(InternalError::LegacyMessage),
            sys::SG_ERR_NO_SESSION => Some(InternalError::NoSession),
            sys::SG_ERR_STALE_KEY_EXCHANGE => {
                Some(InternalError::StaleKeyExchange)
            },
            sys::SG_ERR_UNTRUSTED_IDENTITY => {
                Some(InternalError::UntrustedIdentity)
            },
            sys::SG_ERR_VRF_SIG_VERIF_FAILED => {
                Some(InternalError::VerifySignatureVerificationFailed)
            },
            sys::SG_ERR_INVALID_PROTO_BUF => {
                Some(InternalError::InvalidProtoBuf)
            },
            sys::SG_ERR_FP_VERSION_MISMATCH => {
                Some(InternalError::FPVersionMismatch)
            },
            sys::SG_ERR_FP_IDENT_MISMATCH => {
                Some(InternalError::FPIdentMismatch)
            },
            _ => None,
        }
    }

    /// Get the code which corresponds to this error.
    pub fn code(self) -> i32 {
        match self {
            InternalError::NoMemory => sys::SG_ERR_NOMEM,
            InternalError::InvalidArgument => sys::SG_ERR_INVAL,
            InternalError::Unknown => sys::SG_ERR_UNKNOWN,
            InternalError::DuplicateMessage => sys::SG_ERR_DUPLICATE_MESSAGE,
            InternalError::InvalidKey => sys::SG_ERR_INVALID_KEY,
            InternalError::InvalidKeyId => sys::SG_ERR_INVALID_KEY_ID,
            InternalError::InvalidMAC => sys::SG_ERR_INVALID_MAC,
            InternalError::InvalidMessage => sys::SG_ERR_INVALID_MESSAGE,
            InternalError::InvalidVersion => sys::SG_ERR_INVALID_VERSION,
            InternalError::LegacyMessage => sys::SG_ERR_LEGACY_MESSAGE,
            InternalError::NoSession => sys::SG_ERR_NO_SESSION,
            InternalError::StaleKeyExchange => sys::SG_ERR_STALE_KEY_EXCHANGE,
            InternalError::UntrustedIdentity => sys::SG_ERR_UNTRUSTED_IDENTITY,
            InternalError::VerifySignatureVerificationFailed => {
                sys::SG_ERR_VRF_SIG_VERIF_FAILED
            },
            InternalError::InvalidProtoBuf => sys::SG_ERR_INVALID_PROTO_BUF,
            InternalError::FPVersionMismatch => sys::SG_ERR_FP_VERSION_MISMATCH,
            InternalError::FPIdentMismatch => sys::SG_ERR_FP_IDENT_MISMATCH,
            InternalError::Other(c) => c,
            InternalError::UnknownCiphertextType(_) => {
                sys::SG_ERR_INVALID_PROTO_BUF
            },
            InternalError::SerializationError => sys::SG_ERR_INVALID_PROTO_BUF,
        }
    }
}

/// A helper trait for going from an [`InternalError`] to a `Result`.
pub trait FromInternalErrorCode: Sized {
    /// Make the conversion.
    fn into_result(self) -> Result<(), InternalError>;
}

/// A helper trait for going from a `Result` to an [`InternalError`].
pub trait IntoInternalErrorCode: Sized {
    /// Make the conversion.
    fn into_code(self) -> i32;
}

impl FromInternalErrorCode for isize {
    fn into_result(self) -> Result<(), InternalError> {
        i32::try_from(self).expect("Overflow").into_result()
    }
}

impl FromInternalErrorCode for i32 {
    fn into_result(self) -> Result<(), InternalError> {
        if self == 0 {
            return Ok(());
        }

        match InternalError::from_error_code(self) {
            None => Err(InternalError::Other(self)),
            Some(e) => Err(e),
        }
    }
}

impl<T> IntoInternalErrorCode for Result<T, InternalError> {
    fn into_code(self) -> i32 {
        match self {
            Ok(_) => 0,
            Err(e) => e.code(),
        }
    }
}

impl From<InternalError> for i32 {
    fn from(other: InternalError) -> i32 { other.code() }
}
