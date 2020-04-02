use serde::{Serialize, Deserialize};
use mongodb::{options::CreateCollectionOptions};
use super::{database_errors::DatabaseError};
use config::{Config, Environment, File};

pub struct NewCollection {
    pub name: String,
    pub options: Option<CreateCollectionOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NewCollectionOptions {
    pub name: String,
    pub capped: Option<bool>,
    pub size: Option<i64>,
    pub max: Option<i64>,
}

impl NewCollectionOptions {
    pub fn to_create_collection_options(&self) -> CreateCollectionOptions {
        return CreateCollectionOptions::builder()
            .capped(self.capped)
            .size(self.size)
            .max(self.max)
            .build();
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DB{
    pub uri: String,
    pub name: String,
    pub collections: Option<Vec<NewCollectionOptions>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig{
    pub address: String,
    pub port: u16,
    pub access_log: String,
    pub tls_key: String,
    pub tls_cert: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OauthConfig{
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Vec<String>,
    pub api_key: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailConfig{
    pub from_address: String,
    pub provider: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OauthWrapper{
    pub auths: Vec<OauthConfig>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub database: DB,
    pub server: ServerConfig,
    pub oauth: OauthWrapper,
    pub email: EmailConfig,
}

#[derive(Clone, Debug)]
pub struct ConfigWrapper {
    pub configuration : Configuration,
    pub config : Config,
    pub file: String,
}

impl ConfigWrapper{
    pub fn new(file: &str) -> Result<Self, DatabaseError> {
        let mut settings = Config::new();
        match settings.merge(File::with_name(file)) {
            Ok(_config) => match settings.merge(Environment::with_prefix("app")) {
                Ok(_config) => {
                    Ok(ConfigWrapper{
                        configuration: settings.clone().try_into::<Configuration>().unwrap(),
                        config: settings,
                        file: file.to_string()
                    })
                }
                Err(error) => {
                    return Err(DatabaseError::ConfigError(error));
                }
            },
            Err(error) => {
                return Err(DatabaseError::ConfigError(error));
            }
        }
    }
}