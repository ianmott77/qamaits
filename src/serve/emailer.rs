use lettre::{SendableEmail};
use lettre_email::Email;
use threadpool::ThreadPool;
use curl::easy::{Easy, List};
use super::configuration::OauthConfig;
use base64;

#[derive(Clone, PartialEq, Debug)]
pub struct Emailer {
    pub pool: ThreadPool,
    pub n_threads: usize,
}

impl Emailer {

    pub fn new(num_threads: usize) -> Emailer {
        Emailer{
            pool: ThreadPool::new(num_threads),
            n_threads: num_threads
        }
    }

    pub fn send_email(&self, email: Email, config: OauthConfig) {
        self.pool.execute( move || {
            let sendable : SendableEmail = email.clone().into();
            let msg_64 = base64::encode_config(sendable.message_to_string().unwrap(), base64::URL_SAFE);
            let message = format!("{{ \"raw\" : \"{}\" }}", msg_64);
            let message_bytes =  message.as_bytes();
            let auth_header = format!("Authorization: Bearer {}", config.access_token.unwrap());
            let mut easy = Easy::new();
            let mut list = List::new();
            easy.url(&format!("https://www.googleapis.com/gmail/v1/users/me/messages/send?alt=json&prettyPrint=true&key={}", config.api_key)).unwrap();
            easy.post(true).unwrap();
            list.append(&auth_header).unwrap();
            list.append("Accept: application/json").unwrap();
            list.append("Content-Type: application/json").unwrap();
            easy.http_headers(list).unwrap();
            easy.post_field_size(message_bytes.len() as u64).unwrap();
            easy.post_fields_copy(message_bytes).unwrap();
            easy.transfer().perform().unwrap();
        });
    }

    pub fn build_email(&self, from: String, to: (String, String), subject: String, html: String, text: String) -> Email {
        Email::builder()
        .to(to)
        .from(from)
        .subject(subject)
        .alternative(
            html,
            text,
        )
        .build()
        .unwrap()
    }
}
