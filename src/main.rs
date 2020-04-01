mod serve;
use serve::api::v1::API;
use serve::authorizer::Authorizer;
use serve::configuration::ConfigWrapper;
use serve::database::DatabaseController;
use serve::emailer::Emailer;
use serve::oauth::Oauth;
use serve::server::Server;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use warp::filters::log::Info;
use warp::Filter;

#[tokio::main]
async fn main() {
    let mut config = ConfigWrapper::new("db").unwrap();
    match Server::instance(&config.configuration) {
        Ok(server) => {
            let mut authorizer = Authorizer::new();
            let emailer = Emailer::new(20);
            let mailer = Arc::new(Mutex::new(emailer));
            let serve = Arc::new(Mutex::new(server.clone()));
            let conf = Arc::new(Mutex::new(config.clone().configuration.clone()));
            let mut auths: Vec<String> = Vec::new();
            for i in 0..config.clone().configuration.oauth.auths.len() {
                let auth = config.configuration.oauth.auths[i].clone();
                let serve = Arc::clone(&serve);
                let server = serve.lock().unwrap();
                match DatabaseController::get_oauth_record(&server, auth.clone().name) {
                    Ok(conf) => {
                        config.configuration.oauth.auths[i] = conf;
                    }
                    Err(_) => {
                        let serve = Arc::clone(&serve);
                        authorizer = authorizer.add_oauth(Oauth::new(auth.clone(), serve));
                        auths.push(auth.clone().name);
                    }
                }
            }

            let api_routing = API::setup(mailer, serve, conf);
            let index_file = warp::fs::file("www/index.html");
            let base = warp::get().and(warp::path::end()).and(index_file);
            let assets = warp::path("assets").and(warp::fs::dir("www/assets"));
            let oauth = authorizer.clone().route();
            for prov in auths {
                authorizer.init_authorize(prov);
            }

            let log = warp::log::custom(|info: Info| {
                // Use a log macro, or slog, or println, or whatever!
                let mut usr_agnt = info.user_agent();
                
                if usr_agnt.is_none() {
                    usr_agnt = Some("None");
                }
                let out: String;

                let file_obj = OpenOptions::new().append(true).open("access_log.log");

                match info.remote_addr() {
                    Some(addr) => {
                        out = format!(
                            "{} => [{} {} {} {} {} {}]\n",
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_millis(),
                            addr,
                            info.method(),
                            info.path(),
                            info.status(),
                            info.elapsed().as_nanos().to_string(),
                            usr_agnt.unwrap()
                        );
                    }
                    None => {
                        out = format!(
                            "{} => [{} {} {} {} {}]\n",
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_millis(),
                            info.method(),
                            info.path(),
                            info.status(),
                            info.elapsed().as_nanos().to_string(),
                            usr_agnt.unwrap()
                        );
                    }
                }
                file_obj.unwrap().write(out.as_bytes()).unwrap();
            });

            let routes = base.or(assets).or(api_routing).or(oauth).with(log);

            println!(
                "Running at {:?}:{:?}",
                server.clone().address,
                server.clone().port
            );
            println!("Database: {:?}", server.clone().database.database.name());
            warp::serve(routes)
                .tls()
                .key_path("tls/localhost+2-key.pem")
                .cert_path("tls/localhost+2.pem")
                .run((server.clone().address, server.clone().port))
                .await;
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    }
}
