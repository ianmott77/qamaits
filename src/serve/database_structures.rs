use bcrypt::{hash, verify, BcryptError};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Object {
    pub id: String,
    pub creation_time: String,
    pub the_type: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Verified {
    pub verified: bool,
    pub verify_token: String,
    pub verify_code: String,
    pub verify_time: Option<String>,
    pub expiration_time: String,
}

impl Verified {
    pub fn new() -> Self {
        let creation_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let expiration = creation_time + 86400000;
        return Verified {
            verified: false,
            verify_token: thread_rng().sample_iter(&Alphanumeric).take(256).collect(),
            verify_code: thread_rng().sample_iter(&Alphanumeric).take(6).collect(),
            verify_time: None,
            expiration_time: expiration.to_string(),
        };
    }

    pub fn verify(verifier: &User, verify_token: String, verify_code: String) -> bool {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        if verifier.clone().verify.unwrap().expiration_time.parse::<u128>().unwrap() > current_time {
            if verifier.clone().verify.unwrap().verify_token == verify_token
                && verifier.clone().verify.unwrap().verify_code == verify_code
            {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub email: String,
    pub access_level: String,
    pub verify: Option<Verified>,
    pub access_record: Option<AccessRecord>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub address: Option<String>,
    pub phone_number: Option<String>,

}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AccessRecord {
    pub id: String,
    pub user_id: String,
    pub access_token: String,
    pub creation_time: String,
    pub expires: String,
    pub refresh_token: Option<String>,
}

impl AccessRecord {
    pub fn new(user_id: String) -> Self {
        let creation_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let expiration_time = creation_time + 1200000;
        return AccessRecord {
            id: bson::oid::ObjectId::new().unwrap().to_hex(),
            user_id: user_id,
            access_token: AccessRecord::generate_random(),
            refresh_token: Some(AccessRecord::generate_random()),
            creation_time: creation_time.to_string(),
            expires: expiration_time.to_string(),
        };
    }

    fn generate_random() -> String {
        return thread_rng().sample_iter(&Alphanumeric).take(256).collect();
    }
}

impl User {
    pub fn new(
        id: String,
        username: String,
        password: String,
        email: String,
        access_level: String,
        verifid: Option<Verified>,
        first_name: Option<String>,
        last_name: Option<String>,
        address: Option<String>,
        phone_number: Option<String>
    ) -> Result<Self, BcryptError> {
        match User::hash_pw(password) {
            Ok(pw) => {
                return Ok(User {
                    id: id,
                    username: username,
                    password: pw,
                    email: email,
                    access_level: access_level,
                    verify: verifid,
                    access_record: None,
                    first_name: first_name,
                    last_name: last_name,
                    address: address,
                    phone_number: phone_number
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn hash_pw(password: String) -> Result<String, BcryptError> {
        return hash(password.as_bytes(), 5);
    }

    pub fn verify_pw(password: String, hashed: String) -> Result<bool, BcryptError> {
        return verify(password, &hashed);
    }
}
