# Vulnerable Ruby/Rails Application for SAST Testing
# Each section tests a specific vulnerability category

require 'active_record'
require 'open3'
require 'net/http'
require 'yaml'
require 'json'
require 'erb'
require 'digest'
require 'securerandom'

# ==========================================================================
# 1. SQL Injection
# ==========================================================================
class UsersController < ApplicationController
  def search
    # SQL Injection via string interpolation in where
    @users = User.where("name = '#{params[:name]}'")

    # SQL Injection via find_by_sql
    @results = User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")

    # SQL Injection via execute
    ActiveRecord::Base.connection.execute("DELETE FROM sessions WHERE user_id = '#{params[:id]}'")
  end

  def safe_search
    # SAFE: parameterized query
    @users = User.where("name = ?", params[:name])
    @users = User.where(name: params[:name])
  end
end

# ==========================================================================
# 2. Command Injection
# ==========================================================================
class AdminController < ApplicationController
  def run_command
    # Command injection via system
    system("ls -la #{params[:dir]}")

    # Command injection via exec
    exec("grep #{params[:pattern]} /var/log/app.log")

    # Command injection via backticks
    output = `ping -c 1 #{params[:host]}`

    # Command injection via Open3
    Open3.capture2("nslookup #{params[:domain]}")
  end
end

# ==========================================================================
# 3. Code Injection
# ==========================================================================
class DynamicController < ApplicationController
  def evaluate
    # Code injection via eval
    result = eval(params[:expression])

    # Code injection via instance_eval
    obj.instance_eval(params[:code])

    # Code injection via class_eval
    User.class_eval("def #{params[:method_name]}; end")
  end
end

# ==========================================================================
# 4. XSS
# ==========================================================================
class PostsController < ApplicationController
  def show
    # XSS via raw
    raw(params[:content])

    # XSS via html_safe
    params[:input].html_safe

    # XSS via render inline
    render inline: "<h1>#{params[:title]}</h1>"
  end
end

# ==========================================================================
# 5. Path Traversal
# ==========================================================================
class FilesController < ApplicationController
  def download
    # Path traversal via File.read
    content = File.read(params[:path])

    # Path traversal via File.open
    File.open("/uploads/#{params[:filename]}", 'r') do |f|
      send_data f.read
    end

    # Path traversal via send_file
    send_file(params[:file_path])
  end
end

# ==========================================================================
# 6. Deserialization
# ==========================================================================
class DataController < ApplicationController
  def import
    # Unsafe deserialization via Marshal.load
    data = Marshal.load(params[:data])

    # Unsafe YAML.load with user input
    config = YAML.load(params[:yaml_data])

    # Potentially unsafe JSON.load
    parsed = JSON.load(request.body.read)
  end
end

# ==========================================================================
# 7. SSRF
# ==========================================================================
class ProxyController < ApplicationController
  def fetch
    # SSRF via Net::HTTP
    uri = URI.parse(params[:url])
    response = Net::HTTP.get(uri)

    # SSRF via URI.open
    data = URI.open(params[:url]).read
  end
end

# ==========================================================================
# 8. Mass Assignment
# ==========================================================================
class AccountsController < ApplicationController
  def create
    # Mass assignment via permit!
    user_params = params.require(:user).permit!
    User.create(user_params)

    # Mass assignment without strong params
    User.new(params)
    User.create(params)
    User.update(params)
  end
end

# ==========================================================================
# 9. CSRF
# ==========================================================================
class ApiController < ApplicationController
  # CSRF protection disabled
  skip_before_action :verify_authenticity_token

  protect_from_forgery with: :null_session
end

# ==========================================================================
# 10. Hardcoded Secrets
# ==========================================================================
class Application < Rails::Application
  config.secret_key_base = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

  DATABASE_PASSWORD = "super_secret_db_pass_123"
  API_KEY = "sk-live-abcdef1234567890"

  @api_secret = "my_secret_api_key_value"
  $master_key = "global_master_key_12345"

  config = {
    password: "hardcoded_password_here",
    api_key: "abcdef1234567890abcdef",
    secret_token: "token_value_hardcoded"
  }
end

# ==========================================================================
# 11. Weak Cryptography
# ==========================================================================
class CryptoService
  def hash_password(password)
    # Weak hash: MD5
    Digest::MD5.hexdigest(password)

    # Weak hash: SHA1
    Digest::SHA1.new.update(password)

    # Weak cipher
    cipher = OpenSSL::Cipher.new("DES-CBC")
  end
end

# ==========================================================================
# 12. Insecure Random
# ==========================================================================
class TokenService
  def generate_token
    # Insecure random
    token = rand(1000000).to_s

    # Predictable RNG
    rng = Random.new(42)

    # srand
    srand(12345)
  end
end

# ==========================================================================
# 13. Rails-specific
# ==========================================================================
class PagesController < ApplicationController
  def show
    # Open redirect
    redirect_to params[:url]

    # content_tag with user input
    content_tag(:div, params[:content])

    # render with user-controlled template
    render params[:template]
  end
end

# ==========================================================================
# 14. Sinatra-specific
# ==========================================================================
class MyApp < Sinatra::Base
  # Weak session secret
  set :session_secret, "short"

  get '/page' do
    # Template injection via erb
    erb params[:template]
  end
end

# ==========================================================================
# 15. Open Redirect
# ==========================================================================
class SessionsController < ApplicationController
  def logout
    redirect params[:return_url]
    redirect_to params[:next]
  end
end

# ==========================================================================
# 16. File Upload
# ==========================================================================
class ImageUploader < CarrierWave::Uploader::Base
  mount_uploader :avatar, AvatarUploader
end

class Document < ApplicationRecord
  has_one_attached :file
  has_many_attached :images
end

# ==========================================================================
# 17. Information Disclosure
# ==========================================================================
class ErrorHandler
  def handle(e)
    render json: { error: e.message, trace: e.backtrace }
    e.full_message
  end
end

# ==========================================================================
# 18. Session Issues
# ==========================================================================
class SessionConfig
  def configure
    config.session_store :cookie_store, key: "s"
    session[:user_id] = user.id
  end
end

# ==========================================================================
# 19. Authentication
# ==========================================================================
class DeviseConfig
  def setup
    config.stretches = 4
    skip_before_action :authenticate_user!
  end
end

# ==========================================================================
# 20. Unsafe Reflection
# ==========================================================================
class FactoryController < ApplicationController
  def create
    # Unsafe constantize
    klass = params[:type].constantize
    obj = klass.new

    # Unsafe with interpolation
    "Api::#{params[:version]}::Handler".constantize
  end
end

# ==========================================================================
# 21. Regex DoS
# ==========================================================================
class Validator
  # ReDoS pattern
  EMAIL_REGEX = /^([a-zA-Z0-9]+)*$/
  NESTED = /(a+)+$/

  def validate(input)
    # ReDoS via Regexp.new with user input
    pattern = Regexp.new(params[:regex])
  end
end

# ==========================================================================
# 22. Missing Authorization
# ==========================================================================
class AdminPanel < ApplicationController
  skip_authorization
  skip_authorize_resource
  skip_load_and_authorize_resource
end

# ==========================================================================
# 23. Logging Sensitive Data
# ==========================================================================
class AuthService
  def login(username, password)
    Rails.logger.info("Login attempt: #{password}")
    puts password
    logger.debug("Token: #{token}")
  end
end

# ==========================================================================
# 24. Cookie Security
# ==========================================================================
class CookieHandler
  def set_cookie
    cookies[:session_id] = { value: "abc123" }
    config.force_ssl = false
  end
end

# ==========================================================================
# 25. Timing Attack
# ==========================================================================
class TokenVerifier
  def verify(token)
    # Timing attack: using == for secret comparison
    if @secret_token == params[:token]
      grant_access
    end
  end
end

# ==========================================================================
# 26. Template Injection
# ==========================================================================
class TemplateService
  def render_template
    # SSTI via ERB.new
    template = ERB.new(params[:template])
    template.result(binding)
  end
end

# ==========================================================================
# 27. Dynamic Dispatch
# ==========================================================================
class DynamicService
  def dispatch
    # send with user input
    obj.send(params[:method], params[:args])

    # public_send with user input
    obj.public_send(params[:action])

    # method() with user input
    method(params[:name]).call
  end
end

# ==========================================================================
# 28. Null Safety
# ==========================================================================
class OrderService
  def process
    # NoMethodError risk
    User.find_by(id: params[:id]).name
    Order.first.process!
    items.detect { |i| i.active? }.save
  end
end

# ==========================================================================
# 29. Race Conditions
# ==========================================================================
class WorkerService
  def process_all
    Thread.new do
      @shared_counter += 1
      @@class_var = "modified"
    end
    File.exist?("/tmp/lockfile")
  end
end

# ==========================================================================
# 30. File Permissions
# ==========================================================================
class SetupService
  def configure
    File.chmod(0777, "/tmp/config.yml")
    File.chmod(0666, "/var/data/secrets.yml")
    FileUtils.chmod(0755, "/opt/app/bin/start.sh")
  end
end

# ==========================================================================
# 31+32. Misc: Debug, DoS, Headers
# ==========================================================================
class DebugController < ApplicationController
  def index
    binding.pry
    byebug
    debugger

    sleep(params[:duration])

    response.headers['X-Frame-Options'] = 'ALLOWALL'
  end
end
