#!/usr/bin/perl
# Offensive360 Perl SAST Test Sample - Vulnerable Code
# This file contains intentional vulnerabilities for testing the Perl scanner
# NOTE: Missing -T flag (taint mode not enabled)

# VULN: Missing use strict/warnings (checked at file level)

use CGI;
use DBI;
use LWP::UserAgent;
use Digest::MD5 qw(md5_hex);
use Storable qw(thaw retrieve);
use YAML;

my $q = CGI->new();
my $dbh = DBI->connect("dbi:mysql:testdb", "root", "rootpassword123");

# ============================================================
# SQL Injection
# ============================================================

# VULN: DBI query with variable interpolation
sub get_user {
    my ($username) = @_;
    my $sql = "SELECT * FROM users WHERE name = '$username'";
    my $sth = $dbh->do($sql);
    return $sth;
}

# VULN: prepare with interpolated variable
sub search_products {
    my ($search) = @_;
    my $sth = $dbh->prepare("SELECT * FROM products WHERE name LIKE '%$search%'");
    $sth->execute();
    return $sth->fetchall_arrayref();
}

# VULN: selectall_arrayref with interpolation
sub get_orders {
    my ($customer_id) = @_;
    my $rows = $dbh->selectall_arrayref("SELECT * FROM orders WHERE customer_id = $customer_id");
    return $rows;
}

# VULN: qq{} with SQL and variable
sub delete_user {
    my ($user_id) = @_;
    $dbh->do(qq{DELETE FROM users WHERE id = $user_id});
}

# ============================================================
# Command Injection
# ============================================================

# VULN: system() with variable interpolation
sub ping_host {
    my ($host) = @_;
    system("ping -c 4 $host");
}

# VULN: exec with interpolation
sub run_tool {
    my ($filename) = @_;
    exec("cat /tmp/$filename");
}

# VULN: Backticks with variable
sub get_disk_usage {
    my ($path) = @_;
    my $output = `du -sh $path`;
    return $output;
}

# VULN: qx{} with variable
sub list_directory {
    my ($dir) = @_;
    my $listing = qx{ls -la $dir};
    return $listing;
}

# VULN: open with pipe
sub process_data {
    my ($command) = @_;
    open(my $fh, "| sort | $command");
    print $fh "data\n";
    close($fh);
}

# VULN: Explicit shell invocation
sub run_shell {
    my ($args) = @_;
    system("bash -c '$args'");
}

# ============================================================
# Code Injection (eval)
# ============================================================

# VULN: String eval with variable
sub evaluate_expression {
    my ($expr) = @_;
    my $result = eval "$expr";
    return $result;
}

# VULN: eval with request data
sub process_formula {
    my $formula = $q->param('formula');
    eval($formula);
}

# VULN: eval with user variable
sub dynamic_calc {
    my ($code) = @_;
    eval $code;
    if ($@) { warn "Eval error: $@"; }
}

# VULN: Dynamic file inclusion
sub load_plugin {
    my ($plugin_name) = @_;
    do $plugin_name;
    require $plugin_name;
}

# ============================================================
# XSS
# ============================================================

# VULN: CGI output without encoding
sub display_greeting {
    my $name = $q->param('name');
    print $q->header('text/html');
    print "<h1>Hello, $name!</h1>";
}

# VULN: param() without encoding
sub show_search_results {
    my $query = param('q');
    print "<p>You searched for: $query</p>";
}

# ============================================================
# Path Traversal
# ============================================================

# VULN: open with user-controlled path
sub read_config {
    my ($filename) = @_;
    open(my $fh, "<", "/etc/app/$filename") or die "Cannot open: $!";
    my @lines = <$fh>;
    close($fh);
    return @lines;
}

# VULN: File::Slurp with user path
sub load_template {
    my ($template) = @_;
    my $content = read_file("/templates/$template");
    return $content;
}

# ============================================================
# Two-arg open
# ============================================================

# VULN: Two-argument open with variable
sub old_style_open {
    my ($file) = @_;
    open(FH, $file);
    my @data = <FH>;
    close(FH);
    return @data;
}

# ============================================================
# Deserialization
# ============================================================

# VULN: Storable thaw with untrusted data
sub load_session {
    my ($session_data) = @_;
    my $session = thaw($session_data);
    return $session;
}

# VULN: Storable retrieve from user path
sub load_cache {
    my ($cache_file) = @_;
    my $data = retrieve($cache_file);
    return $data;
}

# VULN: YAML::Load with user input
sub parse_config {
    my ($yaml_string) = @_;
    my $config = YAML::Load($yaml_string);
    return $config;
}

# VULN: Data::Dumper eval
sub load_settings {
    my ($file) = @_;
    my $content = read_file($file);
    my $data;
    eval $content;  # Loading Data::Dumper output
    return $data;
}

# ============================================================
# SSRF
# ============================================================

# VULN: LWP::UserAgent with user URL
sub fetch_url {
    my ($url) = @_;
    my $ua = LWP::UserAgent->new();
    my $response = $ua->get($url);
    return $response->content;
}

# VULN: HTTP::Tiny with user URL
sub proxy_request {
    my ($target_url) = @_;
    my $ua = HTTP::Tiny->new();
    my $response = $ua->get($target_url);
    return $response->{content};
}

# ============================================================
# Hardcoded Secrets
# ============================================================

# VULN: Hardcoded password
my $db_password = "SuperSecret123!Production";
my $api_key = "sk-live-abcdef1234567890abcdef1234567890";
my $secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret";

# VULN: DBI connect with hardcoded credentials
my $dbh2 = DBI->connect(
    "dbi:Pg:dbname=production;host=db.internal",
    "admin",
    password => "Pr0duct10nP@ss!"
);

# ============================================================
# Weak Cryptography
# ============================================================

# VULN: MD5 hash
sub hash_password {
    my ($password) = @_;
    return md5_hex($password);
}

# VULN: SHA1 hash
sub hash_data {
    my ($data) = @_;
    use Digest::SHA1 qw(sha1_hex);
    return sha1_hex($data);
}

# VULN: DES encryption
sub encrypt_data {
    my ($data, $key) = @_;
    use Crypt::DES;
    my $cipher = Crypt::DES->new($key);
    return $cipher->encrypt($data);
}

# ============================================================
# Insecure Random
# ============================================================

# VULN: rand() for security
sub generate_token {
    srand(time());
    my $token = '';
    for (1..32) {
        $token .= chr(int(rand(94)) + 33);
    }
    return $token;
}

# VULN: rand for session ID
sub generate_session_id {
    return int(rand(999999999));
}

# ============================================================
# Regex Injection
# ============================================================

# VULN: User input in regex without \Q\E
sub search_content {
    my ($pattern, $text) = @_;
    if ($text =~ /$pattern/) {
        return $1;
    }
    return undef;
}

# ============================================================
# CGI-specific
# ============================================================

# VULN: CGI header with user value
sub set_redirect {
    my $url = $q->param('redirect_url');
    print $q->redirect($url);
}

# ============================================================
# Symbolic References
# ============================================================

# VULN: no strict refs
sub dynamic_call {
    my ($func_name, @args) = @_;
    no strict 'refs';
    return &{$func_name}(@args);
}

# ============================================================
# Format String
# ============================================================

# VULN: sprintf with user format string
sub format_output {
    my ($format_str, @values) = @_;
    return sprintf($format_str, @values);
}

# ============================================================
# Race Conditions (TOCTOU)
# ============================================================

# VULN: Check then use
sub safe_delete {
    my ($file) = @_;
    if (-f $file) {
        # Race condition: file could change between check and unlink
        unlink($file);
    }
}

# VULN: Check permissions then read
sub read_if_writable {
    my ($file) = @_;
    if (-w $file) {
        open(my $fh, "<", $file);
        my $content = do { local $/; <$fh> };
        close($fh);
        return $content;
    }
}

# ============================================================
# Information Disclosure
# ============================================================

# VULN: confess in production
sub handle_error {
    my ($error) = @_;
    use Carp;
    Carp::confess("Fatal error occurred: $error");
}

# VULN: die with error variable
sub open_file {
    my ($path) = @_;
    open(my $fh, "<", $path) or die "Cannot open $path: $!";
    return $fh;
}

# VULN: fatalsToBrowser
use CGI::Carp qw(fatalsToBrowser);

# ============================================================
# SSL/TLS
# ============================================================

# VULN: SSL verification disabled
sub insecure_request {
    my ($url) = @_;
    my $ua = LWP::UserAgent->new(
        ssl_opts => {
            verify_hostname => 0,
            SSL_verify_mode => SSL_VERIFY_NONE,
        }
    );
    return $ua->get($url);
}

# ============================================================
# Framework-specific
# ============================================================

# VULN: Mojolicious weak secret
sub mojo_app {
    my $app = Mojolicious->new();
    $app->secrets(['weak123']);
}

# VULN: Dancer show_errors
sub dancer_config {
    set show_errors => 1;
    set session_secret => 'short';
}

# ============================================================
# Temporary Files
# ============================================================

# VULN: Insecure temp file
sub create_temp {
    my ($data) = @_;
    my $tmpfile = "/tmp/app_$$" . "_" . time();
    open(my $fh, ">", $tmpfile);
    print $fh $data;
    close($fh);
    return $tmpfile;
}

# ============================================================
# Permissions
# ============================================================

# VULN: World-readable permissions
sub create_config_file {
    my ($path, $content) = @_;
    open(my $fh, ">", $path);
    print $fh $content;
    close($fh);
    chmod(0777, $path);
}

# ============================================================
# Logging Sensitive Data
# ============================================================

# VULN: Logging password
sub log_auth {
    my ($user, $password) = @_;
    warn "Authentication attempt: user=$user, password=$password";
}

# ============================================================
# Cookie Security
# ============================================================

# VULN: Cookie without flags
sub set_session_cookie {
    my ($session_id) = @_;
    my $cookie = CGI::Cookie->new(
        -name  => 'session',
        -value => $session_id,
    );
    print $q->header(-cookie => $cookie);
}

1;
