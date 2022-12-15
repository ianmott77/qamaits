use std::error;
use std::fmt;
use bcrypt::{BcryptError};
use std::time::{SystemTimeError};
use config::{ConfigError};
use mongodb::{error::Error};
use bson::{EncoderError, oid};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InvalidCredentialsError{
    pub details: String,
    pub code: u32,
}

impl fmt::Display for InvalidCredentialsError{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl error::Error for InvalidCredentialsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl InvalidCredentialsError {
    pub fn new(msg: &str) -> InvalidCredentialsError {
        InvalidCredentialsError {details: msg.to_string(), code: 1}
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NotFoundError {
    pub details: String,
    pub code: u32,

}

impl fmt::Display for NotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl error::Error for NotFoundError  {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl NotFoundError {
    pub fn new(msg: &str) -> NotFoundError  {
        NotFoundError {details: msg.to_string(), code: 2}
    }
}


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlreadyExistsError {
    pub details: String,
    pub code: u32,
}

impl fmt::Display for AlreadyExistsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl error::Error for AlreadyExistsError  {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl AlreadyExistsError{
    pub fn new(msg: &str) -> AlreadyExistsError {
        AlreadyExistsError {details: msg.to_string(), code: 3}
    }
}

#[derive(Debug)]
pub enum DatabaseError {
    Error(Error),
    ConfigError(ConfigError),
    BcryptError(BcryptError),
    SystemTimeError(SystemTimeError),
    EncoderError(EncoderError),
    OIDError(oid::Error),
    InvalidCredentialsError(InvalidCredentialsError),
    NotFoundError(NotFoundError),
    AlreadyExistsError(AlreadyExistsError)
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DatabaseError::Error(ref e) => e.fmt(f),
            DatabaseError::ConfigError(ref e) => e.fmt(f),
            DatabaseError::BcryptError(ref e) => e.fmt(f),
            DatabaseError::SystemTimeError(ref e) => e.fmt(f),
            DatabaseError::EncoderError(ref e) => e.fmt(f),
            DatabaseError::OIDError(ref e) => e.fmt(f),
            DatabaseError::InvalidCredentialsError(ref e) => e.fmt(f),
            DatabaseError::NotFoundError(ref e) => e.fmt(f),
            DatabaseError::AlreadyExistsError(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for DatabaseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            DatabaseError::Error(ref e) => Some(e),
            DatabaseError::ConfigError(ref e) => Some(e),
            DatabaseError::BcryptError(ref e) => Some(e),
            DatabaseError::SystemTimeError(ref e) => Some(e),
            DatabaseError::EncoderError(ref e) => Some(e),
            DatabaseError::OIDError(ref e) => Some(e),
            DatabaseError::InvalidCredentialsError(ref e) => Some(e),
            DatabaseError::NotFoundError(ref e) => Some(e),
            DatabaseError::AlreadyExistsError(ref e) => Some(e),
        }
    }
}
