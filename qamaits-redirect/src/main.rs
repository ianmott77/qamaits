use std::env;
use warp;
use warp::filters::path::Tail;
use warp::http::Uri;
use warp::Filter;
use std::sync::{Mutex, Arc};
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let host = Arc::new(Mutex::new(None));
    let mut address: Option<String> = None;
    let port: u16 = 80;
    let mut host_next = false;
    let mut address_next = false;
    for i in 0..args.len() {
        let arg = args[i].clone();
        let host = Arc::clone(&host);
        if address_next && address.is_none(){
            address = Some(arg.clone());
        }

        if host_next && host.lock().unwrap().is_none(){
            *host.lock().unwrap() = Some(arg.clone());
        }

        if arg.clone() == "-host" {
            host_next = true;
        } else if arg.clone() == "-address" {
            address_next = true;
        }
    }
    let ho = Arc::clone(&host);

    let redirect_to_https = warp::path::tail().map(move |tail: Tail| {
        let ho = ho.lock().unwrap();
        let host_name : &str = ho.as_ref().unwrap();
        let redirect: Uri = format!("https://{}/{}", host_name, tail.as_str())
            .parse()
            .unwrap();
        warp::redirect(redirect)
    });

    let add_str = address.clone().unwrap();
    let add_vec: Vec<&str> = add_str.split(".").collect();
    let mut address_arr = [0u8; 4];
    for i in 0..add_vec.len() {
        address_arr[i] = add_vec[i].parse().unwrap();
    }
    println!("Host: {}", host.lock().unwrap().as_ref().unwrap());
    println!("Running at {:?}:{:?}", address, 80);
    warp::serve(redirect_to_https)
        .run((address_arr, port))
        .await;
}
