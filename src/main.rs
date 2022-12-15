mod serve;
use bson::doc;
use bytes::Bytes;
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};
use rustc_serialize::hex::ToHex;
use serde::{Deserialize, Serialize};
use serve::api::v1::API;
use serve::authorizer::Authorizer;
use serve::configuration::ConfigWrapper;
use serve::database::DatabaseController;
use serve::database_structures::User;
use serve::emailer::Emailer;
use serve::oauth::Oauth;
use serve::server::Server;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::io::{Read};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use warp::filters::log::Info;
use warp::Filter;

#[derive(Serialize, Deserialize)]
enum GitHubPayload {
    Null,
    String(String),
    Number(u128),
    Bool(bool),
    Array(Vec<GitHubPayload>),
    Object(HashMap<String, GitHubPayload>),
}

#[tokio::main]
async fn main() {
    let mut config = ConfigWrapper::new("settings").unwrap();
    match Server::instance(&config.clone().configuration) {
        Ok(server) => {
            let mut authorizer = Authorizer::new();
            let emailer = Emailer::new(20);
            let mailer = Arc::new(Mutex::new(emailer));
            let mailer2 = Arc::clone(&mailer.clone());
            let serve = Arc::new(Mutex::new(server.clone()));
            let serve2 = Arc::clone(&serve.clone());
            let conf = Arc::new(Mutex::new(config.clone().configuration.clone()));
            let con = Arc::clone(&conf.clone());
            let co = Arc::clone(&conf.clone());
            let conf2 = Arc::clone(&conf.clone());
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

            let base = warp::any().and(warp::fs::dir(
                config.clone().configuration.server.front_end_directory,
            ));
            let api_routing = API::setup(mailer, serve, conf);
            let oauth = authorizer.clone().route();
            let update_front_end = warp::post()
                .and(warp::path!("update" / "front-end"))
                .and(warp::header("X-Hub-Signature"))
                .and(warp::body::bytes())
                .map(move |sig: String, payload: Bytes| {
                    let config = co.lock().unwrap();
                    let mut build_args = config.clone().server.front_end_build_script;
                    let mut install_args = config.clone().server.front_end_install_script;
                    let mut build_cmd = Command::new(build_args.remove(0));
                    let mut install_cmd = Command::new(install_args.remove(0));
                    build_cmd.args(build_args);
                    install_cmd.args(install_args);

                    let mut hmac = "sha1=".to_string();
                    let digest = MessageDigest::sha1();
                    let key = PKey::hmac(config.clone().server.repository_key.as_bytes()).unwrap();
                    let mut signer = Signer::new(digest, &key).unwrap();
                    signer.update(&payload).unwrap();
                    let hmac_hash = signer.sign_to_vec().unwrap();
                    let hmac_str = hmac_hash.to_hex().to_string();
                    hmac.push_str(&hmac_str);

                    if memcmp::eq(&hmac.as_bytes(), &sig.as_bytes()) {
                        let mut git = Command::new("git");
                        let mut git_path_str = config.clone().server.front_end_build_directory;
                        git_path_str.push_str("/.git");
                        let git_path = Path::new(&git_path_str);
                        if !git_path.exists() {
                            git.arg("clone")
                                .arg(config.clone().server.front_end_repository)
                                .arg(config.clone().server.front_end_build_directory);

                            println!(
                                "Cloning repository: {}",
                                config.clone().server.front_end_repository
                            );

                            let mut clone_hanlde = git.spawn().unwrap();
                            let clone_status = clone_hanlde.wait().unwrap();
                            if clone_status.success() {
                                println!(
                                    "Finished Cloning: {}",
                                    config.clone().server.front_end_repository
                                );
                                println!("Installing...");
                                let current_dir_obj = env::current_dir().unwrap();
                                let current_dir = current_dir_obj.as_path();
                                env::set_current_dir(
                                    config.clone().server.front_end_build_directory,
                                )
                                .unwrap();
                                let mut install_handle = install_cmd.spawn().unwrap();
                                let install_status = install_handle.wait().unwrap();
                                if install_status.success() {
                                    println!("Instalation complete");
                                }
                                env::set_current_dir(current_dir).unwrap();
                            }
                        } else {
                            println!("Pulling: {}", config.clone().server.front_end_repository);
                            git.arg("pull");
                            let current_dir_obj = env::current_dir().unwrap();
                            let current_dir = current_dir_obj.as_path();
                            env::set_current_dir(config.clone().server.front_end_build_directory)
                                .unwrap();
                            let mut git_handle = git.spawn().unwrap();
                            let git_status = git_handle.wait().unwrap();
                            if git_status.success() {
                                println!("Pulled successfully");
                            }
                            env::set_current_dir(current_dir).unwrap();
                        }

                        println!("Building front end");
                        let current_dir_obj = env::current_dir().unwrap();
                        let current_dir = current_dir_obj.as_path();
                        env::set_current_dir(config.clone().server.front_end_build_directory)
                            .unwrap();
                        let mut build_handle = build_cmd.spawn().unwrap();
                        let build_status = build_handle.wait().unwrap();
                        if build_status.success() {
                            println!("Front end built successfully");
                            let front_build = config.clone().server.front_end_build;
                            let front_dir = config.clone().server.front_end_directory;
                            if front_build != front_dir {
                                env::set_current_dir(current_dir).unwrap();
                                let mut copy_cmd = Command::new("cp");
                                copy_cmd.arg("-r").arg(front_build).arg(front_dir);
                                let copy_result = copy_cmd.spawn().unwrap().wait().unwrap();
                                if copy_result.success() {
                                    println!("Moved front end build");
                                }
                            }
                        }
                    }
                    warp::reply()
                });
            let in_browser_routes = warp::path!(String)
                .map(|_| warp::reply::html(fs::read_to_string("www/build/index.html").unwrap()));

            let routes = base
                .or(api_routing)
                .or(oauth)
                .or(update_front_end)
                .or(in_browser_routes)
                .with(log);

            println!(
                "Running at {}:{}",
                config.clone().configuration.server.address,
                server.clone().port
            );
            println!("Database: {}", server.clone().database.database.name());

            match DatabaseController::find(&serve2.lock().unwrap(), doc! {}, "users") {
                Ok(user) => {
                    if user.is_some() {
                        user.unwrap()
                    } else {
                        let mut username_buf = String::new();
                        let mut pass_buf = String::new();
                        let mut email_buf = String::new();
                        println!("Please verify Oauth first!");
                        println!("Please enter an admin username: ");
                        std::io::stdin().read_line(&mut username_buf).unwrap();
                        println!("Please enter an admin password: ");
                        std::io::stdin().read_line(&mut pass_buf).unwrap();
                        println!("Please enter an admin email: ");
                        std::io::stdin().read_line(&mut email_buf).unwrap();
                        println!(
                            "New admin user will be:\nusername: {}\npassword: {}\nemail: {}",
                            username_buf.clone(),
                            pass_buf.clone(),
                            email_buf.clone()
                        );
                        let mut data: HashMap<String, String> = HashMap::new();
                        data.insert("username".to_string(), username_buf.clone());
                        data.insert("password".to_string(), pass_buf.clone());
                        data.insert("email".to_string(), email_buf.clone());
                        match DatabaseController::register_user(
                            &serve2.lock().unwrap(),
                            "administrator".to_string(),
                            &data,
                            &mailer2.lock().unwrap(),
                            &conf2.lock().unwrap(),
                        ) {
                            Ok(user) => {
                                if user.is_some() {
                                    let user_obj: User = user.unwrap();
                                    let verify = user_obj.verify.unwrap();
                                    println!("Verify Token: {}", verify.clone().verify_token);
                                } else {
                                    println!("The user was not added");
                                }
                            }
                            Err(e) => {
                                println!("{:?}", e);
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("{:?}", e);
                    return;
                }
            };

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
