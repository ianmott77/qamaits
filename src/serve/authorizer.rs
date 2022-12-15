use super::oauth::Oauth;
use std::sync::{Arc, Mutex};
use warp;
use warp::Filter;
use warp::Rejection;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Authorizer{
    pub auths: Arc<Mutex<HashMap<String, Oauth>>>
}

impl Authorizer{
    pub fn new() -> Self{
        Authorizer{
            auths: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    pub fn add_oauth(self, auth: Oauth) -> Self{
        self.auths.lock().unwrap().insert(auth.clone().name, auth);
        self
    }
    
    pub fn init_authorize(&self, provider: String){
        let auth = self.auths.lock().unwrap();
        let authr = auth.get(&provider);
        if authr.is_some(){
            println!("\nTo authorize {} browse to:\n{}\n", provider, authr.clone().unwrap().auth_url.clone().into_string());
        }else{
            println!("That OAuth provider wasn't found in your config file")
        }
    }

    pub fn route(self) -> impl Filter<Extract = (warp::reply::Json,), Error = Rejection> + Clone{
        warp::get().and(warp::path!("oauth-validate" / String)).and(warp::query::<HashMap<String, String>>()).map(move | provider: String,query: HashMap<String, String>| {
            let auth = self.auths.lock().unwrap();
            let authr = auth.get(&provider).unwrap();
            authr.clone().handle_response(query)
        })
    }
}