use super::configuration::OauthConfig;
use super::database::DatabaseController;
use super::server::Server;
use bson::doc;
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use url::Url;
use warp;

#[derive(Clone)]
pub struct Oauth {
    pub name: String,
    pub config: OauthConfig,
    pub client: BasicClient,
    pub server: Arc<Mutex<Server>>,
    pub csrf_token: oauth2::CsrfToken,
    pub auth_url: url::Url,
}

impl Oauth {
    pub fn new(config: OauthConfig, serve: Server) -> Self {
        let redirect_url = format!("https://{}/oauth-validate/{}", serve.hostname, config.name);
        let mut client = BasicClient::new(
            ClientId::new(config.clone().client_id),
            Some(ClientSecret::new(config.clone().client_secret)),
            AuthUrl::new(Url::parse(&config.clone().auth_url).unwrap()),
            Some(TokenUrl::new(
                Url::parse(&config.clone().token_url).unwrap(),
            )),
        )
        .set_redirect_url(RedirectUrl::new(
            Url::parse(&redirect_url).unwrap(),
        ));

        for scope in config.clone().scope {
            client = client.add_scope(Scope::new(scope));
        }

        let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random);

        Oauth {
            name: config.clone().name,
            config,
            client,
            server: Arc::new(Mutex::new(serve.clone())),
            csrf_token,
            auth_url,
        }
    }

    pub fn handle_response(mut self, query: HashMap<String, String>) -> warp::reply::Json {
        let code_param = query.get("code").unwrap();
        let state_param = query.get("state").unwrap();
        let code = AuthorizationCode::new(code_param.to_string());
        let state = CsrfToken::new(state_param.to_string());
        if state == self.csrf_token {
            match self.client.exchange_code(code) {
                Ok(tok) => {
                    self.config.access_token = Some(tok.access_token().secret().to_string());
                    self.config.refresh_token =
                        Some(tok.refresh_token().unwrap().secret().to_string());
                    match DatabaseController::add_oauth_record(
                        &self.server.lock().unwrap(),
                        self.config.clone(),
                    ) {
                        Ok(id) => {
                            let message = format!("New Oauth Record Added\nID: {}", id.unwrap());
                            warp::reply::json(&doc! {"status" : "success", "message": message})
                        }
                        Err(e) => {
                            let message = format!("{:?}", e);
                            warp::reply::json(&doc! {"status" : "fail", "message": message})
                        }
                    }
                }
                Err(e) => {
                    let message = format!("{:?}", e);
                    warp::reply::json(&doc! {"status" : "fail", "message": message})
                }
            }
        } else {
            let message = format!("The CSRF Tokens did not match\nOriginal: {:?}\nReturned: {:?}", self.csrf_token, state);
            warp::reply::json(&doc! {"status" : "fail", "message": message})
        }
    }
}
