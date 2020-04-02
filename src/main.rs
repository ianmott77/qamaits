mod serve;
use serve::api::v1::API;
use serve::authorizer::Authorizer;
use serve::configuration::ConfigWrapper;
use serve::database::DatabaseController;
use serve::emailer::Emailer;
use serve::oauth::Oauth;
use serve::server::Server;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use warp::filters::log::Info;
use warp::Filter;

#[tokio::main]
async fn main() {
    let mut config = ConfigWrapper::new("settings").unwrap();
    match Server::instance(&config.clone().configuration) {
        Ok(server) => {
            let mut authorizer = Authorizer::new();
            let emailer = Emailer::new(20);
            let mailer = Arc::new(Mutex::new(emailer));
            let serve = Arc::new(Mutex::new(server.clone()));
            let conf = Arc::new(Mutex::new(config.clone().configuration.clone()));
            let con = Arc::clone(&conf.clone());
            let mut auths: Vec<String> = Vec::new();
            for i in 0..config.clone().configuration.oauth.auths.len() {
                let auth = config.configuration.oauth.auths[i].clone();
                let serve = Arc::clone(&serve);
                let server = serve.lock().unwrap();
                match DatabaseController::get_oauth_record(&server.clone(), auth.clone().name) {
                    Ok(conf) => {
                        config.configuration.oauth.auths[i] = conf;
                    }
                    Err(_) => {
                        let aut = Oauth::new(auth.clone(), server.clone());
                        authorizer = authorizer.add_oauth(aut);
                        auths.push(auth.clone().name);
                    }
                }
            }

            for prov in auths {
                authorizer.init_authorize(prov);
            }

            let log = warp::log::custom(move |info: Info| {
                // Use a log macro, or slog, or println, or whatever!
                let mut usr_agnt = info.user_agent();

                if usr_agnt.is_none() {
                    usr_agnt = Some("None");
                }

                let out: String;

                let con = con.lock().unwrap();
                let path = Path::new(&con.server.access_log);

                let mut file_obj: File;
                if path.exists() {
                    file_obj = OpenOptions::new().append(true).open(path).unwrap();
                } else {
                    file_obj = File::create(path).unwrap();
                }

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
                file_obj.write(out.as_bytes()).unwrap();
            });

            let base = warp::path::end().and(warp::fs::dir("www"));
            let assets = warp::path("assets").and(warp::fs::dir("www/assets"));
            let stat = warp::path("static").and(warp::fs::dir("www/static"));
            let api_routing = API::setup(mailer, serve, conf);
            let oauth = authorizer.clone().route();
            let robots =
                warp::path("robots.txt").map(|| fs::read_to_string("www/robots.txt").unwrap());
            let base_files = warp::path!(String)
                .map(|_| warp::reply::html(fs::read_to_string("www/index.html").unwrap()));

            let routes = robots
                .or(base)
                .or(assets)
                .or(stat)
                .or(api_routing)
                .or(oauth)
                .or(base_files)
                .with(log);

            println!(
                "Running at {}:{}",
                config.clone().configuration.server.address,
                server.clone().port
            );
            println!("Database: {}", server.clone().database.database.name());
            Command::new("./qamaits-redirect")
                .arg("-host")
                .arg(config.clone().configuration.server.hostname)
                .arg("-address")
                .arg(config.clone().configuration.server.address)
                .spawn()
                .unwrap();
            warp::serve(routes)
                .tls()
                .key_path(config.clone().configuration.clone().server.tls_key)
                .cert_path(config.clone().configuration.clone().server.tls_cert)
                .run((server.clone().address, server.clone().port))
                .await;
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    }
}
