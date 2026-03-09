//! Vulnerable Rust application for SAST scanner testing.
//! This file intentionally contains security vulnerabilities across all 30+ categories.

#![allow(unsafe_code)]
#![allow(unused_must_use)]
#![allow(clippy::unwrap_used)]

use std::process::Command;
use std::fs;
use std::io::Read;
use std::collections::HashMap;
use std::sync::Arc;
use std::cell::RefCell;
use std::mem;

use actix_web::{web, App, HttpServer, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use reqwest;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use md5;
use rand::Rng;

// ── 1. Unsafe Code ──────────────────────────────────────

unsafe fn dangerous_pointer_deref(ptr: *const i32) -> i32 {
    *ptr  // Dereferencing raw pointer
}

fn use_transmute() {
    let x: u32 = 42;
    let y: f32 = unsafe { std::mem::transmute(x) };
    println!("Transmuted: {}", y);
}

unsafe impl Send for UnsafeStruct {}

struct UnsafeStruct {
    data: *mut u8,
}

fn raw_pointer_cast() {
    let x = 42i32;
    let ptr = &x as *const i32;  // as *const i32
    unsafe {
        println!("{}", *ptr);
    }
}

// ── 2. Command Injection ────────────────────────────────

fn execute_user_command(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", user_input))
        .output()
        .unwrap();
}

fn run_dynamic_command(cmd_name: &str) {
    Command::new(format!("/usr/bin/{}", cmd_name))
        .arg("--version")
        .output()
        .unwrap();
}

// ── 3. SQL Injection ────────────────────────────────────

fn query_user(db: &rusqlite::Connection, username: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", username);
    db.execute(&format!("SELECT * FROM users WHERE name = '{}'", username), []).unwrap();
    let stmt = db.prepare(&format!("SELECT id FROM accounts WHERE user = '{}'", username));
}

fn diesel_raw_query(conn: &PgConnection, table: &str) {
    sql_query(&format!("SELECT * FROM {} LIMIT 100", table))
        .load::<User>(conn)
        .unwrap();
}

fn sqlx_dynamic_query(pool: &PgPool, filter: &str) {
    sqlx::query(&format!("SELECT * FROM orders WHERE status = '{}'", filter))
        .fetch_all(pool)
        .await
        .unwrap();
}

// ── 4. Path Traversal ───────────────────────────────────

fn read_user_file(file_path: &str) {
    let content = fs::read_to_string(file_path).unwrap();
    println!("File content: {}", content);
}

fn serve_file(request_path: &str) {
    let full_path = PathBuf::from(format!("/var/data/{}", request_path));
    let data = File::open(&full_path).unwrap();
}

// ── 5. XSS ──────────────────────────────────────────────

fn render_html(user_name: &str) -> HttpResponse {
    HttpResponse::Ok().content_type("text/html")
        .body(format!("<h1>Welcome, {}!</h1>", user_name))
}

fn rocket_html_response(input: &str) -> content::Html<String> {
    content::Html(format!("<div>User said: {}</div>", input))
}

fn axum_html(query_param: &str) -> Html<String> {
    Html(format!("<script>alert('{}')</script>", query_param))
}

// ── 6. SSRF ─────────────────────────────────────────────

async fn fetch_url(user_url: &str) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let resp = client.get(user_url).send().await?;
    resp.text().await
}

async fn proxy_request(target_url: &str) {
    let parsed = Url::parse(target_url).unwrap();
    reqwest::get(format!("http://internal-api/{}", target_url)).send().await.unwrap();
}

// ── 7. Deserialization ──────────────────────────────────

fn parse_user_input(body: &[u8]) {
    let data: serde_json::Value = serde_json::from_slice(body).unwrap();
    let config: Config = serde_yaml::from_str(&request_body).unwrap();
    let msg: Message = bincode::deserialize(body).unwrap();
}

// ── 8. Hardcoded Secrets ────────────────────────────────

const DB_PASSWORD: &str = "super_secret_password_123";
const API_KEY: &str = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

fn get_config() -> Config {
    let password = "admin123456";
    let api_key = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_12341234";
    let token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxx";
    let connection_string = "host=db.prod.internal;password=Pr0dP@ss!;database=main";

    Config {
        secret_key: "my-very-secret-key-do-not-share",
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
    }
}

// ── 9. Weak Crypto ──────────────────────────────────────

fn hash_password(password: &str) -> String {
    let digest = md5::compute(password);
    format!("{:x}", digest)
}

fn verify_integrity(data: &[u8]) -> Vec<u8> {
    use sha1;
    Sha1::digest(data).to_vec()
}

fn encrypt_data(key: &[u8], data: &[u8]) {
    let cipher = Des::new(key);
    let rsa_key = Rsa::generate(1024).unwrap();
}

// ── 10. Insecure Random ─────────────────────────────────

fn generate_session_token() -> String {
    let mut rng = rand::thread_rng();
    let token: u64 = rng.gen();
    format!("{:x}", token)
}

fn generate_nonce() -> u64 {
    let rng = SmallRng::seed_from_u64(42);
    rng.gen()
}

// ── 11. Unwrap Overuse ──────────────────────────────────

fn process_data(input: &str) -> String {
    let parsed = input.parse::<i32>().unwrap();
    let config = fs::read_to_string("config.toml").unwrap();
    let value = config.lines().next().unwrap();
    let num = value.trim().parse::<f64>().unwrap();
    let result = some_operation().unwrap();
    let encoded = serde_json::to_string(&result).unwrap();
    encoded
}

// ── 12. Race Conditions ─────────────────────────────────

static mut GLOBAL_COUNTER: u64 = 0;

fn shared_state() {
    let data = Arc::new(vec![1, 2, 3]);
    let data_clone = Arc::new(HashMap::new());

    // RefCell in async context
    let cell = RefCell::new(vec![]);
    tokio::spawn(async move {
        cell.borrow_mut().push(1);
    });
}

// ── 13. Integer Overflow ────────────────────────────────

fn convert_user_input(input: &str) -> u8 {
    let value = input.parse::<u64>().unwrap();
    let small = value as u8;  // truncation from user input
    small
}

fn wrapping_math(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

// ── 14. Insecure TLS ────────────────────────────────────

async fn insecure_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
}

// ── 15. Information Disclosure ──────────────────────────

#[derive(Debug, Clone, Serialize)]
struct UserCredentials {
    username: String,
    password: String,
    api_token: String,
}

#[derive(Debug, Serialize)]
struct SessionConfig {
    session_id: String,
    secret: String,
}

// ── 16. Actix-web Issues ────────────────────────────────

async fn start_actix_server() {
    HttpServer::new(|| {
        App::new()
            .route("/api/users", web::get().to(get_users))
            .route("/api/admin", web::post().to(admin_action))
    })
    .bind("0.0.0.0:8080")
    .unwrap()
    .run()
    .await
    .unwrap();
}

// ── 17. Rocket Issues ───────────────────────────────────

fn rocket_config() {
    let secret_key = "8Xui8SN4mI+7egV/9dlfYYLGQJeEx4+DwmSQLwDVXJg=";
    let environment = "debug";
}

#[get("/api/data")]
fn get_data() -> Json<Vec<Data>> {
    // No auth middleware
    Json(load_all_data())
}

#[post("/api/delete")]
fn delete_item(id: i32) -> Status {
    // No auth middleware
    delete_from_db(id);
    Status::Ok
}

// ── 18. Tokio Blocking in Async ─────────────────────────

async fn bad_async_handler(path: &str) -> String {
    std::thread::sleep(std::time::Duration::from_secs(5));
    let content = std::fs::read_to_string(path).unwrap();
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    content
}

// ── 19. Resource Exhaustion ─────────────────────────────

fn collect_from_request(body: &str) {
    let mut items = Vec::new();
    // Unbounded collection from user input
    for line in body.lines() {
        items.push(line.to_string());
    }

    loop {
        let data = stream.read(&mut buf);
        items.push(data);
    }

    Json::configure(|cfg| cfg.content_type(|_| true));
}

// ── 20. Timing Attacks ──────────────────────────────────

fn verify_password(input: &str, stored_password: &str) -> bool {
    input == password
}

fn check_token(provided: &str, expected_token: &str) -> bool {
    provided.eq(expected_token)  // token == comparison
}

// ── 21. JWT Issues ──────────────────────────────────────

fn create_jwt(user_id: &str) -> String {
    let key = "short";
    let header = Header::new(Algorithm::HS256);
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    encode(&header, &claims, &EncodingKey::from_secret(key.as_ref())).unwrap()
}

fn decode_jwt_unsafe(token: &str) {
    let validation = Validation::new(Algorithm::None);
    decode::<Claims>(token, &DecodingKey::from_secret(b""), &validation).unwrap();
}

// ── 22. CORS Misconfiguration ───────────────────────────

fn configure_cors() -> Cors {
    Cors::permissive()
        .allow_any_origin()
        .allow_any_header()
        .max_age(3600)
}

fn manual_cors_header() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .finish()
}

// ── 23. Missing Auth (see Rocket section above) ─────────

// ── 24. FFI Unsafe Calls ────────────────────────────────

extern "C" {
    fn dangerous_c_function(ptr: *const u8, len: usize) -> i32;
    fn system(command: *const libc::c_char) -> libc::c_int;
}

fn call_libc() {
    unsafe {
        let pid = libc::getpid();
        libc::chmod(b"/tmp/test\0".as_ptr() as *const _, 0o777);
    }
}

// ── 25. Memory Leaks ────────────────────────────────────

fn leak_resources() {
    let important = Box::new(SensitiveData::new());
    mem::forget(important);

    let manual = ManuallyDrop::new(vec![1, 2, 3]);

    let leaked: &'static str = Box::leak(Box::new(String::from("leaked")));
}

// ── 26. Silenced Errors ─────────────────────────────────

fn ignore_errors() {
    let _ = fs::write("/tmp/data.txt", "content");
    let _ = stream.send(message);
    let _ = db.execute("DELETE FROM sessions", []);
    let _ = connection.close();
    let _ = file.flush();
}

// ── 27. File Permissions ────────────────────────────────

fn set_bad_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let perms = Permissions::from_mode(0o777);
    fs::set_permissions("/tmp/sensitive.key", perms).unwrap();

    let tmp = tempfile::Builder::new().prefix("tmp").create().unwrap();
}

// ── 28. Logging Sensitive Data ──────────────────────────

fn log_user_data(user: &User) {
    println!("User login with password: {}", user.password);
    log::info!("Auth token: {}", user.api_token);
    tracing::debug!("Secret key used: {}", config.secret);
    eprintln!("Credential verification for: {}", credential);
}

// ── 29. Open Redirect ───────────────────────────────────

fn handle_redirect(url: &str) -> Redirect {
    Redirect::to(format!("{}", url))
}

fn set_location_header(target: &str) -> HttpResponse {
    HttpResponse::Found()
        .insert_header(("Location", format!("/goto?url={}", target)))
        .finish()
}

// ── 30. Clippy Security Lints ───────────────────────────

#[allow(clippy::panic)]
fn risky_indexing(data: &[u8], idx: usize) {
    let value = data[idx];
    println!("Got: {}", value);
}

#[allow(clippy::todo)]
fn incomplete_auth() {
    todo!("Implement proper authentication");
}

fn main() {
    println!("This is a vulnerable Rust application for testing SAST scanners.");
    println!("DO NOT use this code in production!");
}
