// Comprehensive Rust vulnerability test samples for SAST scanner testing
// This file intentionally contains security vulnerabilities for testing purposes.
// DO NOT use this code in production.

use std::process::Command;
use std::fs;
use std::io::{Read, Write};
use std::ptr;
use std::mem;
use std::env;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ============================================================================
// 1. Unsafe Code - Raw pointer dereference
// ============================================================================
fn vulnerable_unsafe_pointer() {
    unsafe {
        let x: *const i32 = ptr::null();
        let val = *x as *mut i32; // raw pointer dereference
        println!("Value: {}", *val);
    }
}

// Unsafe function declaration
pub unsafe fn dangerous_operation(ptr: *mut u8, len: usize) {
    let slice = std::slice::from_raw_parts(ptr, len);
    println!("Data: {:?}", slice);
}

// Unsafe trait impl
unsafe impl Send for UnsafeStruct {}
struct UnsafeStruct {
    data: *mut u8,
}

// Transmute in unsafe block
fn type_punning() {
    unsafe {
        let x: u64 = 42;
        let y: f64 = std::mem::transmute(x);
        println!("Transmuted: {}", y);
    }
}

// ============================================================================
// 2. Command Injection
// ============================================================================
fn run_user_command(user_input: &str) {
    let output = Command::new(user_input)
        .output()
        .expect("Failed to execute");
    println!("{:?}", output);
}

fn command_with_args(filename: &str) {
    let _result = Command::new("grep")
        .arg(format!("-r {} /etc/", filename))
        .output();
}

fn shell_injection(user_data: &str) {
    let cmd = format!("sh -c 'echo {}'", user_data);
    let _output = Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .output();
}

// ============================================================================
// 3. SQL Injection
// ============================================================================
fn sql_injection_format(username: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", username);
    // execute_query(&query);
    println!("{}", query);
}

fn sql_injection_concat(table: String) {
    let query = "DELETE FROM " + &table + " WHERE id = 1";
    println!("{}", query);
}

fn raw_sql_usage() {
    // Simulating diesel raw_sql usage
    // diesel::sql_query("SELECT * FROM users")
    //     .execute_unprepared(&conn);
    let _ = sql_query("SELECT * FROM users WHERE id = 1");
}

fn sql_query(_q: &str) -> bool { true }

// ============================================================================
// 4. Path Traversal
// ============================================================================
fn read_user_file(user_path: &str) {
    let content = fs::read_to_string(user_path).unwrap();
    println!("{}", content);
}

fn write_to_path(filename: &str) {
    let path = format!("/uploads/{}/../../etc/passwd", filename);
    fs::write(Path::new(&path), "data").unwrap();
}

use std::path::Path;

fn file_operations(user_dir: &str) {
    let entries = fs::read_dir(user_dir).unwrap();
    for entry in entries {
        println!("{:?}", entry);
    }
}

// ============================================================================
// 5. Deserialization
// ============================================================================
fn deserialize_untrusted(data: &str) {
    let parsed: HashMap<String, String> = serde_json::from_str(data).unwrap();
    println!("{:?}", parsed);
}

fn bincode_deserialize(bytes: &[u8]) {
    let result: Vec<u64> = bincode::deserialize(bytes).unwrap();
    println!("{:?}", result);
}

fn yaml_deserialize(input: &str) {
    let config: HashMap<String, String> = serde_yaml::from_str(input).unwrap();
    println!("{:?}", config);
}

// ============================================================================
// 6. Hardcoded Secrets
// ============================================================================
const API_KEY: &str = "sk-proj-abc123def456ghi789jkl012mno345pqr678";
static DATABASE_URL: &str = "postgres://admin:SuperSecret123@prod-db.example.com/mydb";

fn hardcoded_credentials() {
    let password = "MyS3cretP@ssw0rd!";
    let api_key = "AKIAFAKEKEY1234567890";
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let secret_key: &str = "a1b2c3d4e5f6g7h8i9j0secretkey";
    let connection_string: &str = "Server=prod.db.com;Database=main;User=admin;Password=hunter2";
    let private_key: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
    println!("{} {} {} {} {} {}", password, api_key, token, secret_key, connection_string, private_key);
}

// ============================================================================
// 7. Weak Cryptography
// ============================================================================
use md5;
use sha1;

fn weak_hash(data: &[u8]) {
    let hash = md5::compute(data);
    println!("MD5: {:x}", hash);

    let sha = sha1::Sha1::new();
    println!("SHA1: {}", sha.digest().to_string());
}

fn weak_rsa() {
    let key = Rsa::generate(1024).unwrap(); // Weak key size
    println!("Key generated");
}

fn ecb_encryption(data: &[u8]) {
    // Using ECB mode for encryption - insecure
    let cipher = Ecb::new(key, &Default::default());
    let encrypted = cipher.encrypt(data);
}

// ============================================================================
// 8. Insecure Random
// ============================================================================
fn generate_token() {
    let mut rng = SmallRng::from_entropy();
    let token: u64 = rng.gen();
    println!("Token: {}", token);
}

fn weak_session_id() {
    let session_key: u64 = thread_rng().gen();
    println!("Session: {}", session_key);
}

// ============================================================================
// 9. Race Conditions
// ============================================================================
static mut GLOBAL_COUNTER: i32 = 0;

fn race_condition_static() {
    unsafe {
        GLOBAL_COUNTER += 1;
    }
}

fn potential_deadlock() {
    let lock_a = Arc::new(Mutex::new(0));
    let lock_b = Arc::new(Mutex::new(0));

    let a = lock_a.lock().unwrap();
    let b = lock_b.lock().unwrap(); // Potential deadlock if another thread locks b then a
    println!("{} {}", a, b);
}

// ============================================================================
// 10. Memory Safety
// ============================================================================
fn memory_forget() {
    let data = vec![1, 2, 3];
    std::mem::forget(data); // Memory leak
}

fn manual_drop_misuse() {
    let value = ManuallyDrop::new(String::from("leaked"));
    // Never dropped - resource leak
}

fn from_raw_parts_danger() {
    unsafe {
        let ptr = 0x1234 as *const u8;
        let slice = std::slice::from_raw_parts(ptr, 100);
        println!("{:?}", slice);
    }
}

fn box_from_raw_danger() {
    let ptr = Box::into_raw(Box::new(42));
    unsafe {
        let _ = Box::from_raw(ptr);
        let _ = Box::from_raw(ptr); // Double free!
    }
}

fn pointer_arithmetic() {
    unsafe {
        let arr = [1u8, 2, 3, 4];
        let ptr = arr.as_ptr();
        let val = *ptr.offset(100); // Out of bounds
        println!("{}", val);
    }
}

// ============================================================================
// 11. Integer Overflow
// ============================================================================
fn integer_overflow_unsafe() {
    unsafe {
        let a: u32 = u32::MAX;
        let b: u32 = a + 1; // Overflow in unsafe
        println!("{}", b);
    }
}

fn truncating_cast(big_value: u64) -> u8 {
    big_value as u8 // Truncating cast
}

fn another_truncating(size: usize) -> u32 {
    size as u32 // Truncating on 64-bit
}

// ============================================================================
// 12. Panic in Production
// ============================================================================
fn unwrap_chain(input: &str) -> i32 {
    input.parse::<i32>().unwrap()
}

fn expect_usage(data: &[u8]) -> String {
    String::from_utf8(data.to_vec()).expect("Invalid UTF-8")
}

fn todo_left_in_code() {
    todo!("Implement authentication check")
}

fn unimplemented_handler() {
    unimplemented!("This feature is not yet implemented")
}

fn direct_indexing(data: &[i32], index: usize) -> i32 {
    data[index] // Can panic on out of bounds
}

fn panic_explicitly() {
    panic!("Something went terribly wrong");
}

// ============================================================================
// 13. Error Handling
// ============================================================================
fn ignored_result() {
    let _ = fs::remove_file("/tmp/important.log");
}

fn ignored_result2() {
    let _ = send_email("user@example.com");
}

fn send_email(_to: &str) -> Result<(), String> { Ok(()) }

fn error_info_discarded() -> Result<(), String> {
    let data = fs::read_to_string("config.toml")
        .map_err(|_| "failed".to_string())?;
    Ok(())
}

// ============================================================================
// 14. Actix-web Security Issues
// ============================================================================
use actix_web::{web, App, HttpServer, HttpResponse};
use actix_cors::Cors;

fn configure_cors() -> Cors {
    Cors::permissive() // Allows everything - insecure!
}

fn configure_cors2() -> Cors {
    Cors::default().allowed_origin("*")
}

#[get("/api/admin/users")]
async fn admin_users(db: web::Data<DbPool>) -> HttpResponse {
    // No authentication extractor!
    let users = db.get_all_users().await;
    HttpResponse::Ok().json(users)
}

#[post("/api/user/data")]
async fn user_data_handler(body: web::Json<UserRequest>) -> HttpResponse {
    match process(&body) {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(err) => HttpResponse::InternalServerError().body(format!("Error: {:?}", err)),
    }
}

// ============================================================================
// 15. Rocket Issues
// ============================================================================
#[derive(FromForm)]
struct LoginForm {
    username: String,
    password: String,
}

// ============================================================================
// 16. Tokio/Async Issues
// ============================================================================
async fn blocking_in_async() {
    // Blocking call in async context
    std::thread::sleep(std::time::Duration::from_secs(5));
    let data = std::fs::read_to_string("large_file.txt").unwrap();
    println!("{}", data);
}

async fn unbounded_channel_usage() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send("data").unwrap();
}

async fn detached_task() {
    tokio::spawn(async {
        // This task's errors are silently swallowed
        risky_operation().await;
    });
}

async fn risky_operation() {}

// ============================================================================
// 17. FFI Safety
// ============================================================================
extern "C" {
    fn external_function(ptr: *const u8, len: usize) -> i32;
    fn another_ffi(data: *mut libc::c_void) -> *mut libc::c_void;
}

fn cstring_misuse(user_input: &str) {
    let c_str = CString::new(user_input).unwrap(); // Panics on NUL byte
    unsafe {
        let raw = CStr::from_ptr(c_str.as_ptr());
    }
}

use std::ffi::{CString, CStr};

// ============================================================================
// 18. Information Disclosure
// ============================================================================
#[derive(Debug, Clone)]
struct UserCredentials {
    username: String,
    password: String,
    api_key: String,
    token: String,
}

fn log_sensitive_data(creds: &UserCredentials) {
    println!("Login attempt with password: {}", creds.password);
    eprintln!("API key used: {}", creds.api_key);
    dbg!(&creds.token);
}

// ============================================================================
// 19. SSL/TLS Misconfiguration
// ============================================================================
fn insecure_https_client() {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
}

fn old_tls() {
    let config = SslConfig::new()
        .min_protocol_version(Protocol::Tls10);
}

fn http_url_usage() {
    let api = "http://api.production.com/v1/data";
    let cdn = "http://cdn.example.net/assets/main.js";
}

// ============================================================================
// 20. File Permissions
// ============================================================================
fn insecure_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o777);
    fs::set_permissions("/tmp/sensitive_data", perms).unwrap();
}

fn world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o666);
    fs::set_permissions("/var/data/config", perms).unwrap();
}

fn insecure_temp() {
    let _ = File::create("/tmp/session_data.txt").unwrap();
}

// ============================================================================
// 21. Regex DoS
// ============================================================================
fn catastrophic_regex(input: &str) {
    let re = Regex::new("(a+)+b").unwrap();
    re.is_match(input);
}

fn another_bad_regex(input: &str) {
    let re = Regex::new("(.*a){10}").unwrap();
    re.is_match(input);
}

// ============================================================================
// 22. Type Confusion
// ============================================================================
fn transmute_confusion() {
    unsafe {
        let bytes: &[u8] = b"hello";
        let string: &str = std::mem::transmute(bytes); // bytes to str without UTF-8 check
    }
}

fn transmute_copy_danger() {
    unsafe {
        let x: u32 = 42;
        let y: f64 = std::mem::transmute_copy(&x);
        println!("{}", y);
    }
}

// ============================================================================
// 23. Missing Input Validation
// ============================================================================
async fn no_validation_handler(body: web::Json<CreateUser>) -> HttpResponse {
    // No validation of any fields
    let user = create_user(body.into_inner()).await;
    HttpResponse::Ok().json(user)
}

fn unvalidated_env_var() {
    let port = env::var("PORT").unwrap();
    let host = env::var("DATABASE_HOST").unwrap();
}

// ============================================================================
// 24. Resource Leaks
// ============================================================================
fn leaked_file() {
    File::open("/dev/urandom");  // Handle not stored
}

fn into_raw_leak() {
    let boxed = Box::new(vec![1, 2, 3]);
    let ptr = Box::into_raw(boxed);
    // ptr is never freed - memory leak
}

fn infinite_loop_no_break() {
    loop {
        // No break condition - runs forever
        process_data();
    }
}

fn process_data() {}

// ============================================================================
// 25. Timing Attacks
// ============================================================================
fn verify_password(input: &str, stored_hash: &str) -> bool {
    input == stored_hash // Non-constant-time comparison
}

fn verify_token(provided_token: &str, expected_token: &str) -> bool {
    provided_token == expected_token // Timing attack vulnerable
}

fn check_hmac(computed_mac: &[u8], received_mac: &[u8]) -> bool {
    computed_mac == received_mac // Should use constant_time_eq
}

// ============================================================================
// 26. Format String / XSS
// ============================================================================
fn html_response(user_name: &str) {
    let body = String::new();
    write!(&mut std::io::stdout(), "<html><body>{}</body></html>", user_name);
}

// ============================================================================
// 27. Deprecated / Unsafe Functions
// ============================================================================
fn set_env_unsafely() {
    std::env::set_var("PATH", "/usr/bin");
    std::env::remove_var("TEMP");
}

fn unchecked_utf8(bytes: Vec<u8>) -> String {
    unsafe {
        String::from_utf8_unchecked(bytes)
    }
}

fn uninitialized_memory() {
    unsafe {
        let value: u64 = MaybeUninit::uninit().assume_init();
        println!("{}", value);
    }
}

fn main() {
    println!("This file is for SAST scanner testing only!");
}
