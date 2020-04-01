use super::configuration::Configuration;
use super::database::DatabaseController;
use super::database_errors::DatabaseError;

#[derive(Clone)]
pub struct Server {
    pub database: DatabaseController,
    pub address: [u8; 4],
    pub port: u16,
}

impl Server {
    pub fn instance(config: &Configuration) -> Result<Server, DatabaseError> {
        let conf = Some(config).clone();
        match DatabaseController::create_database_from_config(conf.clone().unwrap()) {
            Ok(db) => {
                let address_str_arr: Vec<&str> =
                    conf.as_ref().unwrap().server.address.split(".").collect();
                let mut address_arr: [u8; 4] = [0, 0, 0, 0];
                for i in 0..address_str_arr.len() {
                    address_arr[i] = address_str_arr[i].parse().unwrap();
                }
                Ok(Server {
                    database: db,
                    address: address_arr,
                    port: conf.as_ref().unwrap().server.port,
                })
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}
