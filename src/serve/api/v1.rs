use super::super::database::DatabaseController;
use super::super::database_errors::DatabaseError;
use super::super::emailer::Emailer;
use super::super::server::Server;
use super::super::configuration::Configuration;
use bson::doc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use warp::reject::Rejection;
use warp::Filter;

#[derive(Serialize, Deserialize)]
pub struct APIFail {
    pub response: String,
}

#[derive(Serialize, Deserialize)]
pub struct APIResponse<T> {
    pub status: String,
    pub message: Option<String>,
    pub data: Option<T>,
}

#[derive(Clone)]
pub struct API {
    pub server: Server,
}

impl API {
    fn init_routes() -> impl Filter<
        Extract = (u8, String, HashMap<String, HashMap<String, String>>),
        Error = Rejection,
    > + Copy {
        warp::post().and(warp::path!("api" / u8 / String).and(warp::body::json()))
    }

    pub fn setup(mailer: Arc<Mutex<Emailer>>, server: Arc<Mutex<Server>>, config: Arc<Mutex<Configuration>>) -> impl Filter<Extract = (warp::reply::Json,), Error = Rejection> + Clone{
        let routes = API::init_routes();
        routes.map(
            move |_version: u8, action: String, map: HashMap<String, HashMap<String, String>>| {
                API::map_actions(_version, &mailer.lock().unwrap(), &server.lock().unwrap(), action, map, &config.lock().unwrap()).unwrap()
            }
        )
    }

    pub fn map_actions(
        _version: u8,
        emailer: &Emailer,
        server: &Server,
        action: String,
        map: HashMap<String, HashMap<String, String>>,
        config: &Configuration
    ) -> Result<warp::reply::Json, DatabaseError> {
        let data = map.get("data");
        if action.eq("register") {
            match DatabaseController::register_user(
                server,
                "subscriber".to_string(),
                data.clone().unwrap(),
                emailer,
                config
            ) {
                Ok(user) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "success".to_string(),
                        message: None,
                        data: Some(doc! {
                            "user_id": user.clone().unwrap().id,
                            "verify_token": user.clone().unwrap().verify.unwrap().verify_token
                        }),
                    }))
                }
                Err(e) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "fail".to_string(),
                        message: Some("Registration failed!".to_string()),
                        data: Some(format!("{:?}", e)),
                    }))
                }
            }
        } else if action.eq("login") {
            match DatabaseController::login_user(server, data.clone().unwrap()) {
                Ok(record) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "success".to_string(),
                        message: Some("Success".to_string()),
                        data: Some(doc! {
                            "access_token": record.clone().unwrap().access_token,
                            "refresh_token": record.clone().unwrap().refresh_token.unwrap(),
                            "expires": record.clone().unwrap().expires
                        }),
                    }))
                }
                Err(e) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "fail".to_string(),
                        message: Some("Login Failed".to_string()),
                        data: Some(format!("{:?}", e)),
                    }))
                }
            }
        } else if action.eq("exchange") {
            let username = data.clone().unwrap().get("username").unwrap();
            let refresh_token = data.clone().unwrap().get("refresh_token").unwrap();
            let access_token = data.clone().unwrap().get("access_token").unwrap();
            match DatabaseController::exchange_refresh_token(
                server,
                access_token.to_string(),
                refresh_token.to_string(),
                username.to_string(),
            ) {
                Ok(record) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "success".to_string(),
                        message: Some("Success".to_string()),
                        data: Some(doc! {
                            "access_token": record.clone().unwrap().access_token,
                            "refresh_token": record.clone().unwrap().refresh_token.unwrap(),
                            "expires": record.clone().unwrap().expires
                        }),
                    }))
                }
                Err(e) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "fail".to_string(),
                        message: Some("Login Failed".to_string()),
                        data: Some(format!("{:?}", e)),
                    }))
                }
            }
        } else if action.eq("verify") {
            let username = data.clone().unwrap().get("username").unwrap();
            let verify_token = data.clone().unwrap().get("verify_token").unwrap();
            let verify_code = data.clone().unwrap().get("verify_code").unwrap();
            match DatabaseController::verify_user(
                server,
                username.to_string(),
                verify_token.to_string(),
                verify_code.to_string(),
            ) {
                Ok(user) => {
                    let vtoken = user.verify.clone().unwrap().verify_token;
                    let vtime = user.verify.clone().unwrap().verify_time.unwrap();
                    Ok(warp::reply::json(&APIResponse {
                        status: "success".to_string(),
                        message: Some(format!("{} is now verified", username)),
                        data: Some(doc! {
                            "verify_token": vtoken,
                            "verify_time" : vtime
                        }),
                    }))
                }
                Err(e) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "fail".to_string(),
                        message: Some("Verify Failed".to_string()),
                        data: Some(format!("{:?}", e)),
                    }))
                }
            }
        } else if action.eq("logout") {
            let username = data.clone().unwrap().get("username").unwrap();
            let access_token = data.clone().unwrap().get("access_token").unwrap();
            match DatabaseController::logout(server, username.to_string(), access_token.to_string()) {
                Ok(_res) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "success".to_string(),
                        message: Some(format!("{} is logged out", username)),
                        data: Some("Logged Out!"),
                    }))
                }
                Err(e) => {
                    Ok(warp::reply::json(&APIResponse {
                        status: "fail".to_string(),
                        message: Some("Logout Failed".to_string()),
                        data: Some(format!("{:?}", e)),
                    }))
                }
            }
        } else {
            Ok(warp::reply::json(&APIResponse {
                status: "fail".to_string(),
                message: Some("Invalid data".to_string()),
                data: Some(""),
            }))
        }
    }
}
