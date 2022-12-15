use super::configuration::{Configuration, NewCollection, OauthConfig};
use super::database_errors::{
    AlreadyExistsError, DatabaseError, InvalidCredentialsError, NotFoundError,
};
use serde::{de::DeserializeOwned};
use super::database_structures::{AccessRecord, Object, User, Verified};
use super::server::Server;
use super::emailer::Emailer;
use bson::doc;
use mongodb::{options::FindOneOptions, Client, Collection, Database};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Clone)]
pub struct DatabaseController {
    pub uri: String,
    pub database: Database,
}

impl DatabaseController {
    pub fn create_database(
        uri: &str,
        name: &str,
        mut collections: Vec<NewCollection>,
    ) -> Result<Database, DatabaseError> {
        let client = Client::with_uri_str(uri).unwrap();
        let database = client.database(name);
        for j in 0..collections.len() {
            let opt = collections[j].options.take().unwrap();
            let result = database.create_collection(&(collections[j].name), opt);
            let current_collections = database.list_collection_names(None).unwrap();
            let mut insert = true;
            for k in 0..current_collections.len() {
                if String::from(&(collections[j].name)) == current_collections[k] {
                    insert = false;
                    break;
                }
            }
            if insert {
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        return Err(DatabaseError::Error(error));
                    }
                }
            }
        }
        return Ok(database);
    }

    pub fn create_database_from_config(
        config: &Configuration,
    ) -> Result<DatabaseController, DatabaseError> {
        let collections = config.clone().database.collections.unwrap();
        let mut coll_vec = vec![];
        for i in 0..collections.len() {
            coll_vec.push(NewCollection {
                name: String::from(&(collections[i].name)),
                options: Some(collections[i].to_create_collection_options()).take(),
            });
        }
        match DatabaseController::create_database(
            &(config.database.uri),
            &(config.database.name),
            coll_vec,
        ) {
            Ok(database) => {
                return Ok(DatabaseController {
                    uri: config.clone().database.uri,
                    database: database,
                });
            }
            Err(error) => {
                return Err(error);
            }
        }
    }

    pub fn find_user(
        collection: &Collection,
        username: &str,
        email: Option<String>,
    ) -> Result<User, DatabaseError> {
        let filter;
        if email.is_some() {
            filter = doc! { "$or": [{"username" : username }, {"email": email.unwrap()}]};
        } else {
            filter = doc! {"username" : username };
        }
        let options = FindOneOptions::builder().build();
        match collection.find_one(filter, options) {
            Ok(doc) => {
                if doc.is_some() {
                    let d = doc.unwrap();
                    let new_doc = bson::Bson::Document(d);
                    let user: User = bson::from_bson::<User>(new_doc).unwrap();
                    return Ok(user);
                } else {
                    return Err(DatabaseError::NotFoundError(NotFoundError::new(&format!(
                        "{} was not found",
                        username
                    ))));
                }
            }
            Err(e) => {
                return Err(DatabaseError::Error(e));
            }
        }
    }

    pub fn register_user(
        server: &Server,
        access_level: String,
        data: &HashMap<String, String>,
        emailer: &Emailer,
        config: &Configuration
    ) -> Result<Option<User>, DatabaseError> {
        let password : String;
        let username : String;
        let email : String;
        let first_name: Option<String>;
        let last_name : Option<String>;
        let phone_number : Option<String>;
        let address : Option<String>;
        
        let mut field = "password";
        if data.get(field).is_some() {
            password = data.get(field).unwrap().to_string();
        }else{
            return Err(DatabaseError::InvalidCredentialsError(InvalidCredentialsError::new(&format!("Missing {} field", field))));
        }

        field = "username";
        if data.get(field).is_some() {
            username = data.get(field).unwrap().to_string();
        }else{
            return Err(DatabaseError::InvalidCredentialsError(InvalidCredentialsError::new(&format!("Missing {} field", field))));
        }

        field = "email";
        if data.get(field).is_some() {
            email = data.get(field).unwrap().to_string();
        }else{
            return Err(DatabaseError::InvalidCredentialsError(InvalidCredentialsError::new(&format!("Missing {} field", field))));
        }
        
        field = "first_name";
        if data.get(field).is_some() {
            first_name = Some(data.get(field).unwrap().to_string());
        }else{
            first_name = None;
        }

        field = "last_name";
        if data.get(field).is_some() {
            last_name = Some(data.get(field).unwrap().to_string());
        }else{
            last_name = None;
        }

        field = "address";
        if data.get(field).is_some() {
            address = Some(data.get(field).unwrap().to_string());
        }else{
            address = None;
        }

        field = "phone_number";
        if data.get(field).is_some() {
            phone_number = Some(data.get(field).unwrap().to_string());
        }else{
            phone_number = None;
        }

        println!("here");
        if validator::validate_email(email.clone()) {
            match DatabaseController::user_exists(server, &username, &email) {
                Err(_e) => match DatabaseController::add_object(server, "user") {
                    Ok(id) => {
                        if id.is_some() {
                            match DatabaseController::add_user(
                                server,
                                id.unwrap(),
                                username,
                                password,
                                email,
                                access_level,
                                Verified::new(),
                                first_name,
                                last_name,
                                address,
                                phone_number
                            ) {
                                Ok(user) => {
                                    if user.is_some() {
                                        let email = emailer.build_email(config.clone().email.from_address, (
                                            user.clone().unwrap().email,
                                            user.clone().unwrap().username,
                                        ), "Login Verification Code".to_string(),
                                        format!(
                                            "<h2><u>Your verification code is</u>:<b> {}</b></h2>",
                                            user.clone().unwrap().verify.unwrap().verify_code
                                        ),
                                        format!(
                                            "Your verification code is: {}",
                                            user.clone().unwrap().verify.unwrap().verify_code
                                        ));
                                        match DatabaseController::find::<OauthConfig>(server, doc!{"name": config.clone().email.provider}, "oauth"){
                                            Ok(auth) => {
                                                if auth.is_some() {
                                                    emailer.send_email(email.clone(), auth.unwrap());
                                                }else{
                                                    return Ok(None);
                                                }
                                            }
                                            Err(e) => {
                                                return Err(e);
                                            }
                                        }
                                        return Ok(user);
                                    } else {
                                        return Ok(None);
                                    }
                                }
                                Err(e) => {
                                    return Err(e);
                                }
                            }
                        } else {
                            return Ok(None);
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                Ok(user) => {
                    if user.username == username {
                        return Err(DatabaseError::AlreadyExistsError(AlreadyExistsError::new(
                            "There is already someone wth that username",
                        )));
                    } else {
                        return Err(DatabaseError::AlreadyExistsError(AlreadyExistsError::new(
                            "There is already an account with that email address",
                        )));
                    }
                }
            }
        } else {
            return Err(DatabaseError::InvalidCredentialsError(
                InvalidCredentialsError::new("This is an invalid email address"),
            ));
        }
    }

    pub fn user_exists(server: &Server, username: &str, email: &str) -> Result<User, DatabaseError> {
        let users_collection = server.database.database.collection("users");
        match DatabaseController::find_user(&users_collection, username, Some(email.to_string())) {
            Ok(user) => return Ok(user),
            Err(e) => return Err(e),
        }
    }

    pub fn verify_user(
        server: &Server,
        username: String,
        verify_token: String,
        verify_code: String,
    ) -> Result<User, DatabaseError> {
        let users_collection = server.database.database.collection("users");
        match DatabaseController::find_user(&users_collection, &username, None) {
            Ok(mut user) => {
                if Verified::verify(&user, verify_token, verify_code) {
                    let mut ver = user.clone().verify.unwrap();
                    ver.verify_time = Some(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_millis()
                            .to_string(),
                    );
                    ver.verified = true;
                    user.verify = Some(ver);
                    match DatabaseController::update_user(
                        &users_collection,
                        user.clone().username,
                        user.clone(),
                    ) {
                        Ok(user) => {
                            return Ok(user.unwrap());
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                } else {
                    return Err(DatabaseError::InvalidCredentialsError(
                        InvalidCredentialsError::new("Invalid verify credentials"),
                    ));
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn logout(server: &Server, username: String, access_token: String) -> Result<bool, DatabaseError> {
        let users_collection = server.database.database.collection("users");
        match DatabaseController::find_user(&users_collection, &username, None) {
            Ok(user) => {
                if user.clone().access_record.is_some() {
                    if user.clone().access_record.unwrap().access_token == access_token {
                        match DatabaseController::update_access_record(
                            &users_collection,
                            user,
                            None,
                        ) {
                            Ok(_acc) => {
                                return Ok(true);
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(DatabaseError::NotFoundError(NotFoundError::new(&format!(
                            "{} has no access record please login",
                            user.clone().username
                        ))));
                    }
                } else {
                    return Err(DatabaseError::InvalidCredentialsError(
                        InvalidCredentialsError::new("Invalid username or access token"),
                    ));
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn add_user(
        server: &Server,
        id: String,
        username: String,
        password: String,
        email: String,
        access_level: String,
        verified: Verified,
        first_name: Option<String>,
        last_name: Option<String>,
        address: Option<String>,
        phone_number: Option<String>,
    ) -> Result<Option<User>, DatabaseError> {
        match User::new(id, username, password, email, access_level, Some(verified), first_name, last_name, address, phone_number) {
            Ok(user) => {
                let users_collection = server.database.database.collection("users");
                let new_user = bson::to_bson(&user).unwrap();
                if let bson::Bson::Document(document) = new_user {
                    match users_collection.insert_one(document, None) {
                        Ok(_result) => {
                            return Ok(Some(user));
                        }
                        Err(e) => {
                            return Err(DatabaseError::Error(e));
                        }
                    }
                } else {
                    return Ok(None);
                }
            }
            Err(e) => {
                return Err(DatabaseError::BcryptError(e));
            }
        }
    }

    pub fn add_object(server: &Server, the_type: &str) -> Result<Option<String>, DatabaseError> {
        let objects = server.database.database.collection("objects");
        match DatabaseController::generate_object_id() {
            Ok(oid) => match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => {
                    let object_raw = Object {
                        the_type: String::from(the_type),
                        creation_time: n.as_millis().to_string(),
                        id: oid,
                    };
                    match bson::to_bson(&object_raw) {
                        Ok(bson_object) => {
                            if let bson::Bson::Document(document) = bson_object {
                                match objects.insert_one(document, None) {
                                    Ok(_result) => {
                                        return Ok(Some(object_raw.id));
                                    }
                                    Err(e) => {
                                        return Err(DatabaseError::Error(e));
                                    }
                                }
                            } else {
                                return Ok(None);
                            }
                        }
                        Err(e) => {
                            return Err(DatabaseError::EncoderError(e));
                        }
                    }
                }
                Err(e) => {
                    return Err(DatabaseError::SystemTimeError(e));
                }
            },
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn add_oauth_record(server: &Server, mut oauth: OauthConfig) -> Result<Option<String>, DatabaseError>{
        match DatabaseController::add_object(server, "oauth") {
            Ok(id) => {
                oauth.id = Some(id.unwrap());
                let oauth_collection = server.database.database.collection("oauth");
                match bson::to_bson(&oauth) {
                    Ok(bson_object) => {
                        if let bson::Bson::Document(document) = bson_object {
                            match oauth_collection.insert_one(document, None) {
                                Ok(_result) => {
                                    return Ok(Some(oauth.id.unwrap()));
                                }
                                Err(e) => {
                                    return Err(DatabaseError::Error(e));
                                }
                            }
                        } else {
                            return Ok(None);
                        }
                    }
                    Err(e) => {
                        return Err(DatabaseError::EncoderError(e));
                    }
                }
            }
            Err(e) =>{
                return Err(e);
            }
        }
    }

    pub fn find<T>(server: &Server, query: bson::Document, collection: &str)  -> Result<Option<T>, DatabaseError>
    where T: DeserializeOwned {
        let collect = server.database.database.collection(&collection);
        let options = FindOneOptions::builder().build();
        match collect.find_one(query, options) {
            Ok(doc) => {
                if doc.is_some() {
                    let d = doc.unwrap();
                    let new_doc = bson::Bson::Document(d);
                    return Ok(Some(bson::from_bson::<T>(new_doc).unwrap()));
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                return Err(DatabaseError::Error(e));
            }
        }
    }

    pub fn get_oauth_record(server: &Server, name: String) -> Result<OauthConfig, DatabaseError>{
        match DatabaseController::find::<OauthConfig>(server, doc!{"name" : name.clone()}, "oauth"){
            Ok(config) => {
                if config.is_some(){
                    Ok(config.unwrap())
                }else{
                    Err(DatabaseError::NotFoundError(NotFoundError::new(&format!("Oauth config for {} was not found", name.clone()))))
                }
            }
            Err(e) => Err(e)
        }
    }

    pub fn get_acccess_record(server: &Server, username: String) -> Result<Option<AccessRecord>, DatabaseError> {
        let users_collection = server.database.database.collection("users");
        match DatabaseController::find_user(&users_collection, &username, None) {
            Ok(user) => {
                if user.access_record.is_some() {
                    return Ok(user.access_record);
                } else {
                    return Err(DatabaseError::NotFoundError(NotFoundError::new(
                        "User access record doesn't exist was not found!",
                    )));
                }
            }
            Err(e) => {
                println!("{:?}", e);
                return Err(e);
            }
        }
    }

    pub fn add_access_record(
        collection: &Collection,
        mut user: User,
        data: Option<AccessRecord>,
    ) -> Result<Option<AccessRecord>, DatabaseError> {
        user.access_record = data;
        match DatabaseController::update_user(&collection, user.clone().username, user.clone()) {
            Ok(_res) => {
                return Ok(Some(user.clone().access_record.unwrap()));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn exchange_refresh_token(
        server: &Server,
        access_token: String,
        refresh_token: String,
        username: String,
    ) -> Result<Option<AccessRecord>, DatabaseError> {
        let users_collection = server.database.database.collection("users");
        match DatabaseController::find_user(&users_collection, &username, None) {
            Ok(user) => {
                if user.clone().access_record.unwrap().refresh_token.unwrap() == refresh_token
                    && user.clone().access_record.unwrap().access_token == access_token
                {
                    return DatabaseController::update_access_record(
                        &users_collection,
                        user.clone(),
                        Some(AccessRecord::new(user.clone().id)),
                    );
                } else {
                    return Err(DatabaseError::NotFoundError(NotFoundError::new(
                        "The specified access token was not found!",
                    )));
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn update_access_record(
        collection: &Collection,
        mut user: User,
        record: Option<AccessRecord>,
    ) -> Result<Option<AccessRecord>, DatabaseError> {
        user.access_record = record;
        match DatabaseController::update_user(collection, user.clone().username, user) {
            Ok(us) => {
                if us.is_some() {
                    return Ok(us.unwrap().access_record);
                } else {
                    return Err(DatabaseError::NotFoundError(NotFoundError::new(&format!(
                        "{} was not found",
                        us.unwrap().username
                    ))));
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn update_user(
        collection: &Collection,
        username: String,
        user: User,
    ) -> Result<Option<User>, DatabaseError> {
        let query = doc! {"username": username};
        match bson::to_bson(&user) {
            Ok(bson_object) => {
                if let bson::Bson::Document(document) = bson_object {
                    match collection.update_one(query, document, None) {
                        Ok(_result) => {
                            return Ok(Some(user));
                        }
                        Err(e) => {
                            return Err(DatabaseError::Error(e));
                        }
                    }
                } else {
                    return Ok(None);
                }
            }
            Err(e) => {
                return Err(DatabaseError::EncoderError(e));
            }
        }
    }

    pub fn generate_object_id() -> Result<String, DatabaseError> {
        match bson::oid::ObjectId::new() {
            Ok(oid) => {
                return Ok(oid.to_hex());
            }
            Err(e) => {
                return Err(DatabaseError::OIDError(e));
            }
        }
    }

    pub fn login_user(
        server: &Server,
        data: &HashMap<String, String>,
    ) -> Result<Option<AccessRecord>, DatabaseError> {
        let username = data.get("username").unwrap().to_string();
        let password = data.get("password").unwrap().to_string();
        let users_collection = server.database.database.collection("users");
        match DatabaseController::find_user(&users_collection, &username, None) {
            Ok(user) => match User::verify_pw(password, user.clone().password) {
                Ok(res) => {
                    if user.clone().verify.unwrap().verified {
                        if res {
                            match DatabaseController::get_acccess_record(server, username) {
                                Ok(acc) => {
                                    if SystemTime::now()
                                        .duration_since(SystemTime::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        < acc.clone().unwrap().expires.parse::<u128>().unwrap()
                                    {
                                        return Ok(Some(acc.unwrap()));
                                    } else {
                                        let access = AccessRecord::new(user.clone().id);
                                        return DatabaseController::add_access_record(
                                            &users_collection,
                                            user,
                                            Some(access),
                                        );
                                    }
                                }
                                Err(_e) => {
                                    let access = AccessRecord::new(user.clone().id);
                                    return DatabaseController::add_access_record(
                                        &users_collection,
                                        user,
                                        Some(access),
                                    );
                                }
                            }
                        } else {
                            return Err(DatabaseError::InvalidCredentialsError(
                                InvalidCredentialsError::new("Invalid Passoword"),
                            ));
                        }
                    } else {
                        return Err(DatabaseError::InvalidCredentialsError(
                            InvalidCredentialsError::new("Account has not yet been verified"),
                        ));
                    }
                }
                Err(e) => {
                    return Err(DatabaseError::BcryptError(e));
                }
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
}
