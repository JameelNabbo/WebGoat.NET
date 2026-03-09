#!/usr/bin/env ruby
# frozen_string_literal: true

# ==========================================================================
# Offensive360 Ruby SAST Scanner
# Comprehensive AST-based static analysis for Ruby code.
# Runs as a Sinatra/WEBrick HTTP service on port 9007.
# ==========================================================================

require 'sinatra/base'
require 'webrick'
require 'json'
require 'securerandom'
require 'parser/current'
require 'logger'
require 'digest'

# Opt-in to latest parser AST format
Parser::Builders::Default.emit_lambda              = true
Parser::Builders::Default.emit_procarg0            = true
Parser::Builders::Default.emit_encoding            = true
Parser::Builders::Default.emit_index               = true
Parser::Builders::Default.emit_arg_inside_procarg0 = true

SCANNER_LOG = Logger.new(File.join(__dir__, 'scanner.log'), 3, 1_048_576)
SCANNER_LOG.level = Logger::INFO

# ==========================================================================
# Vulnerability data class
# ==========================================================================
Vuln = Struct.new(
  :title, :severity, :confidence, :cwe, :owasp,
  :file_path, :line_number, :column_offset, :end_line,
  :code_snippet, :remediation, :category, :data_flow,
  keyword_init: true
) do
  def to_h
    {
      id:           SecureRandom.uuid,
      title:        title,
      severity:     severity,
      confidence:   confidence,
      cwe:          cwe,
      owasp:        owasp,
      filePath:     file_path,
      lineNumber:   line_number || 0,
      columnOffset: column_offset || 0,
      endLine:      end_line || line_number || 0,
      codeSnippet:  code_snippet || '',
      remediation:  remediation || '',
      category:     category || '',
      dataFlow:     (data_flow || []).map { |n| { file: n[:file], line: n[:line], code: n[:code] } }
    }
  end
end

# ==========================================================================
# Source-line helper
# ==========================================================================
class SourceMap
  def initialize(source, file_path)
    @lines = source.lines
    @file_path = file_path
  end

  def snippet(line, context = 1)
    return '' unless line && line > 0
    from = [line - context, 1].max
    to   = [line + context, @lines.size].min
    (from..to).map { |n| "#{n}: #{@lines[n - 1]}" }.join.rstrip
  end

  def line_text(line)
    return '' unless line && line > 0 && line <= @lines.size
    @lines[line - 1].to_s.strip
  end
end

# ==========================================================================
# Taint-tracking helpers
# ==========================================================================
module TaintSources
  RAILS_PARAMS = %w[params request cookies session env headers].freeze
  SINATRA_PARAMS = %w[params request env].freeze

  # Returns true if the node looks like it carries external / user input
  def self.tainted?(node)
    return false unless node.is_a?(Parser::AST::Node)
    case node.type
    when :send
      recv, method_name, * = *node
      # params[:x], params.fetch, request.body, etc.
      if recv.is_a?(Parser::AST::Node)
        if recv.type == :send
          _, recv_name, * = *recv
          return true if RAILS_PARAMS.include?(recv_name.to_s)
        elsif recv.type == :lvar || recv.type == :ivar
          recv_name = recv.children[0].to_s.delete('@')
          return true if RAILS_PARAMS.include?(recv_name)
        end
      end
      # Direct params reference
      return true if method_name && RAILS_PARAMS.include?(method_name.to_s)
      # gets, readline etc.
      return true if %i[gets readline readlines read_nonblock].include?(method_name)
    when :lvar
      name = node.children[0].to_s
      return true if RAILS_PARAMS.include?(name)
    when :gvar
      return true if node.children[0].to_s.start_with?('$')
    end
    false
  end

  # Check if any child of node is tainted
  def self.any_child_tainted?(node)
    return false unless node.is_a?(Parser::AST::Node)
    return true if tainted?(node)
    node.children.any? { |c| any_child_tainted?(c) }
  end
end

# ==========================================================================
# AST walker base
# ==========================================================================
class ASTWalker
  attr_reader :vulns

  def initialize(file_path, source)
    @file_path = file_path
    @source    = source
    @src_map   = SourceMap.new(source, file_path)
    @vulns     = []
    @class_stack = []
    @method_stack = []
  end

  def walk(node)
    return unless node.is_a?(Parser::AST::Node)
    visit(node)
    node.children.each { |c| walk(c) }
  end

  private

  def visit(node); end

  def loc_line(node)
    node.loc&.expression&.line rescue nil
  end

  def loc_col(node)
    node.loc&.expression&.column rescue nil
  end

  def loc_end(node)
    node.loc&.expression&.last_line rescue loc_line(node)
  end

  def snippet(node, ctx = 2)
    @src_map.snippet(loc_line(node), ctx)
  end

  def add_vuln(node, title:, severity:, confidence:, cwe:, owasp:, remediation:, category:, data_flow: [])
    @vulns << Vuln.new(
      title:         title,
      severity:      severity,
      confidence:    confidence,
      cwe:           cwe,
      owasp:         owasp,
      file_path:     @file_path,
      line_number:   loc_line(node),
      column_offset: loc_col(node),
      end_line:      loc_end(node),
      code_snippet:  snippet(node),
      remediation:   remediation,
      category:      category,
      data_flow:     data_flow
    )
  end

  # Helper: check if node is a string interpolation (dstr) containing tainted data
  def interpolation_with_taint?(node)
    return false unless node.is_a?(Parser::AST::Node)
    return false unless node.type == :dstr
    node.children.any? { |c| c.is_a?(Parser::AST::Node) && c.type == :begin && TaintSources.any_child_tainted?(c) }
  end

  # Helper: method name matches
  def send_method?(node, *names)
    return false unless node.type == :send
    _, method_name, * = *node
    names.include?(method_name)
  end

  # Helper: receiver name
  def receiver_name(node)
    return nil unless node.is_a?(Parser::AST::Node) && node.type == :send
    recv = node.children[0]
    return nil unless recv.is_a?(Parser::AST::Node)
    case recv.type
    when :const then recv.children[1].to_s
    when :send  then receiver_chain(recv)
    when :lvar, :ivar then recv.children[0].to_s.delete('@')
    else nil
    end
  end

  def receiver_chain(node)
    parts = []
    current = node
    while current.is_a?(Parser::AST::Node) && current.type == :send
      parts.unshift(current.children[1].to_s)
      current = current.children[0]
    end
    if current.is_a?(Parser::AST::Node) && current.type == :const
      parts.unshift(current.children[1].to_s)
    end
    parts.join('.')
  end

  # Collect all :send method names in subtree
  def collect_sends(node)
    result = []
    return result unless node.is_a?(Parser::AST::Node)
    if node.type == :send
      result << node.children[1]
    end
    node.children.each { |c| result.concat(collect_sends(c)) }
    result
  end

  # Find all nodes matching a type
  def find_nodes(node, type)
    result = []
    return result unless node.is_a?(Parser::AST::Node)
    result << node if node.type == type
    node.children.each { |c| result.concat(find_nodes(c, type)) }
    result
  end

  # Check if a :sym node or :str node matches
  def sym_or_str?(node, *names)
    return false unless node.is_a?(Parser::AST::Node)
    val = case node.type
          when :sym then node.children[0].to_s
          when :str then node.children[0].to_s
          else nil
          end
    names.map(&:to_s).include?(val)
  end
end

# ==========================================================================
# Category 1: SQL Injection
# ==========================================================================
class SQLInjectionChecker < ASTWalker
  SQL_METHODS = %i[where find_by_sql execute select_all select_one
                   select_value select_values count_by_sql joins
                   having order group pluck].freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    return unless SQL_METHODS.include?(method_name)

    args.each do |arg|
      if interpolation_with_taint?(arg)
        add_vuln(node,
          title:       "SQL Injection via #{method_name}",
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-89',
          owasp:       'A03:2021',
          remediation: "Use parameterized queries: #{method_name}([\"col = ?\", value]) or hash conditions: #{method_name}(col: value)",
          category:    'SQL Injection'
        )
      elsif arg.is_a?(Parser::AST::Node) && arg.type == :dstr
        # String interpolation even without obvious taint source is suspicious in SQL
        add_vuln(node,
          title:       "Potential SQL Injection via string interpolation in #{method_name}",
          severity:    'High',
          confidence:  'Medium',
          cwe:         'CWE-89',
          owasp:       'A03:2021',
          remediation: "Use parameterized queries instead of string interpolation in #{method_name}",
          category:    'SQL Injection'
        )
      end
    end
  end
end

# ==========================================================================
# Category 2: Command Injection
# ==========================================================================
class CommandInjectionChecker < ASTWalker
  CMD_METHODS = %i[system exec spawn popen popen2 popen2e popen3].freeze
  OPEN3_METHODS = %i[capture2 capture2e capture3 popen2 popen2e popen3 pipeline pipeline_r pipeline_rw pipeline_w].freeze

  private

  def visit(node)
    case node.type
    when :send
      _, method_name, *args = *node

      # Kernel.system, system(), exec()
      if CMD_METHODS.include?(method_name)
        if args.any? { |a| interpolation_with_taint?(a) || TaintSources.any_child_tainted?(a) }
          add_vuln(node,
            title:       "Command Injection via #{method_name}",
            severity:    'Critical',
            confidence:  'High',
            cwe:         'CWE-78',
            owasp:       'A03:2021',
            remediation: "Use array form: system('cmd', arg1, arg2) to avoid shell interpolation. Validate and sanitize all user input.",
            category:    'Command Injection'
          )
        elsif args.any? { |a| a.is_a?(Parser::AST::Node) && a.type == :dstr }
          add_vuln(node,
            title:       "Potential Command Injection via #{method_name} with interpolation",
            severity:    'High',
            confidence:  'Medium',
            cwe:         'CWE-78',
            owasp:       'A03:2021',
            remediation: "Use array form of #{method_name} to prevent shell injection. Never interpolate user data into commands.",
            category:    'Command Injection'
          )
        end
      end

      # Open3 methods
      recv_name = receiver_name(node)
      if recv_name == 'Open3' && OPEN3_METHODS.include?(method_name)
        if args.any? { |a| interpolation_with_taint?(a) || TaintSources.any_child_tainted?(a) }
          add_vuln(node,
            title:       "Command Injection via Open3.#{method_name}",
            severity:    'Critical',
            confidence:  'High',
            cwe:         'CWE-78',
            owasp:       'A03:2021',
            remediation: "Pass command and arguments as separate parameters to Open3.#{method_name}.",
            category:    'Command Injection'
          )
        end
      end

    when :xstr
      # Backtick execution `cmd`
      if node.children.any? { |c| c.is_a?(Parser::AST::Node) && TaintSources.any_child_tainted?(c) }
        add_vuln(node,
          title:       'Command Injection via backtick execution',
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-78',
          owasp:       'A03:2021',
          remediation: 'Avoid backtick execution with user input. Use Open3 with array arguments instead.',
          category:    'Command Injection'
        )
      elsif node.children.any? { |c| c.is_a?(Parser::AST::Node) && c.type == :begin }
        add_vuln(node,
          title:       'Potential Command Injection via backtick execution with interpolation',
          severity:    'High',
          confidence:  'Medium',
          cwe:         'CWE-78',
          owasp:       'A03:2021',
          remediation: 'Avoid backtick execution with interpolation. Use Open3 with array arguments instead.',
          category:    'Command Injection'
        )
      end
    end
  end
end

# ==========================================================================
# Category 3: Code Injection
# ==========================================================================
class CodeInjectionChecker < ASTWalker
  EVAL_METHODS = %i[eval instance_eval class_eval module_eval instance_exec class_exec module_exec].freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    if EVAL_METHODS.include?(method_name)
      if args.any? { |a| TaintSources.any_child_tainted?(a) || interpolation_with_taint?(a) }
        add_vuln(node,
          title:       "Code Injection via #{method_name} with user input",
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-94',
          owasp:       'A03:2021',
          remediation: "Never pass user input to #{method_name}. Use a whitelist approach or safe alternatives.",
          category:    'Code Injection'
        )
      elsif args.any? { |a| a.is_a?(Parser::AST::Node) && a.type == :dstr }
        add_vuln(node,
          title:       "Code Injection via #{method_name} with string interpolation",
          severity:    'High',
          confidence:  'Medium',
          cwe:         'CWE-94',
          owasp:       'A03:2021',
          remediation: "Avoid string interpolation in #{method_name}. Use safe alternatives.",
          category:    'Code Injection'
        )
      end
    end
  end
end

# ==========================================================================
# Category 4: XSS (Cross-Site Scripting)
# ==========================================================================
class XSSChecker < ASTWalker
  XSS_METHODS = %i[raw html_safe mark_safe].freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    if XSS_METHODS.include?(method_name)
      if TaintSources.any_child_tainted?(node)
        add_vuln(node,
          title:       "Cross-Site Scripting (XSS) via #{method_name} with user input",
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-79',
          owasp:       'A03:2021',
          remediation: "Never call #{method_name} on user-supplied data. Use proper output encoding or sanitize_html.",
          category:    'XSS'
        )
      else
        add_vuln(node,
          title:       "Potential XSS via #{method_name}",
          severity:    'Medium',
          confidence:  'Medium',
          cwe:         'CWE-79',
          owasp:       'A03:2021',
          remediation: "Review usage of #{method_name}. Ensure the value is never derived from user input.",
          category:    'XSS'
        )
      end
    end

    # render inline: with user input
    if method_name == :render
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :hash
          arg.children.each do |pair|
            next unless pair.is_a?(Parser::AST::Node) && pair.type == :pair
            key, val = pair.children
            if sym_or_str?(key, 'inline')
              if TaintSources.any_child_tainted?(val) || interpolation_with_taint?(val)
                add_vuln(node,
                  title:       'XSS via render inline with user input',
                  severity:    'Critical',
                  confidence:  'High',
                  cwe:         'CWE-79',
                  owasp:       'A03:2021',
                  remediation: 'Never pass user input to render inline. Use templates with automatic escaping.',
                  category:    'XSS'
                )
              end
            end
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 5: Path Traversal
# ==========================================================================
class PathTraversalChecker < ASTWalker
  FILE_METHODS = %i[read open write binread binwrite readlines foreach new delete rename].freeze

  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, *args = *node

    # File.read(params[:file]), File.open(...)
    recv_name = receiver_name(node)
    if %w[File IO FileUtils Dir Pathname].include?(recv_name) && FILE_METHODS.include?(method_name)
      if args.any? { |a| TaintSources.any_child_tainted?(a) || interpolation_with_taint?(a) }
        add_vuln(node,
          title:       "Path Traversal via #{recv_name}.#{method_name}",
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-22',
          owasp:       'A01:2021',
          remediation: "Validate file paths against a whitelist. Use File.expand_path and verify the result is within an allowed directory.",
          category:    'Path Traversal'
        )
      end
    end

    # send_file with user input
    if method_name == :send_file
      if args.any? { |a| TaintSources.any_child_tainted?(a) || interpolation_with_taint?(a) }
        add_vuln(node,
          title:       'Path Traversal via send_file with user input',
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-22',
          owasp:       'A01:2021',
          remediation: 'Validate file path and ensure it resolves within an allowed directory before passing to send_file.',
          category:    'Path Traversal'
        )
      end
    end
  end
end

# ==========================================================================
# Category 6: Deserialization
# ==========================================================================
class DeserializationChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, *args = *node
    recv_name = receiver_name(node)

    # Marshal.load
    if recv_name == 'Marshal' && method_name == :load
      add_vuln(node,
        title:       'Unsafe Deserialization via Marshal.load',
        severity:    'Critical',
        confidence:  'High',
        cwe:         'CWE-502',
        owasp:       'A08:2021',
        remediation: 'Never use Marshal.load with untrusted data. Use JSON.parse or a safe serialization format.',
        category:    'Deserialization'
      )
    end

    # YAML.load (unsafe before Ruby 3.1 / Psych 4)
    if recv_name == 'YAML' && method_name == :load
      if args.any? { |a| TaintSources.any_child_tainted?(a) }
        add_vuln(node,
          title:       'Unsafe Deserialization via YAML.load with user input',
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-502',
          owasp:       'A08:2021',
          remediation: 'Use YAML.safe_load instead of YAML.load. It restricts allowed classes.',
          category:    'Deserialization'
        )
      else
        add_vuln(node,
          title:       'Potentially Unsafe Deserialization via YAML.load',
          severity:    'High',
          confidence:  'Medium',
          cwe:         'CWE-502',
          owasp:       'A08:2021',
          remediation: 'Use YAML.safe_load instead of YAML.load to prevent arbitrary object instantiation.',
          category:    'Deserialization'
        )
      end
    end

    # JSON.load (can instantiate objects via create_additions)
    if recv_name == 'JSON' && method_name == :load
      add_vuln(node,
        title:       'Potentially Unsafe JSON.load (supports create_additions)',
        severity:    'Medium',
        confidence:  'Low',
        cwe:         'CWE-502',
        owasp:       'A08:2021',
        remediation: 'Use JSON.parse instead of JSON.load. JSON.load may support create_additions for object instantiation.',
        category:    'Deserialization'
      )
    end
  end
end

# ==========================================================================
# Category 7: SSRF
# ==========================================================================
class SSRFChecker < ASTWalker
  HTTP_CLASSES = %w[Net::HTTP HTTParty RestClient Faraday Typhoeus Excon HTTP].freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node
    recv_name = receiver_name(node)

    # Net::HTTP.get, RestClient.get, etc.
    if HTTP_CLASSES.any? { |c| recv_name&.include?(c.split('::').last) }
      if args.any? { |a| TaintSources.any_child_tainted?(a) || interpolation_with_taint?(a) }
        add_vuln(node,
          title:       "Server-Side Request Forgery (SSRF) via #{recv_name}.#{method_name}",
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-918',
          owasp:       'A10:2021',
          remediation: 'Validate and whitelist URLs before making HTTP requests. Block internal/private IP ranges.',
          category:    'SSRF'
        )
      end
    end

    # open-uri: open(params[:url]) or URI.open(params[:url])
    if method_name == :open && recv_name == 'URI'
      if args.any? { |a| TaintSources.any_child_tainted?(a) }
        add_vuln(node,
          title:       'SSRF via URI.open with user input',
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-918',
          owasp:       'A10:2021',
          remediation: 'Validate and whitelist URLs. Never pass user input directly to URI.open.',
          category:    'SSRF'
        )
      end
    end
  end
end

# ==========================================================================
# Category 8: Mass Assignment
# ==========================================================================
class MassAssignmentChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # permit! (permits all parameters - dangerous)
    if method_name == :permit!
      add_vuln(node,
        title:       'Mass Assignment via permit! (allows all parameters)',
        severity:    'High',
        confidence:  'High',
        cwe:         'CWE-915',
        owasp:       'A04:2021',
        remediation: 'Use permit(:field1, :field2) to explicitly whitelist allowed parameters instead of permit!.',
        category:    'Mass Assignment'
      )
    end

    # Model.new(params) / Model.create(params) without strong parameters
    if %i[new create create! update update! assign_attributes].include?(method_name)
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :send
          _, arg_method, * = *arg
          if arg_method == :params
            add_vuln(node,
              title:       "Mass Assignment via #{method_name}(params) without strong parameters",
              severity:    'High',
              confidence:  'Medium',
              cwe:         'CWE-915',
              owasp:       'A04:2021',
              remediation: "Use strong parameters: #{method_name}(params.require(:model).permit(:field1, :field2))",
              category:    'Mass Assignment'
            )
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 9: CSRF
# ==========================================================================
class CSRFChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # skip_before_action :verify_authenticity_token
    if %i[skip_before_action skip_before_filter].include?(method_name)
      args.each do |arg|
        if sym_or_str?(arg, 'verify_authenticity_token')
          add_vuln(node,
            title:       'CSRF Protection Disabled (skip_before_action :verify_authenticity_token)',
            severity:    'High',
            confidence:  'High',
            cwe:         'CWE-352',
            owasp:       'A01:2021',
            remediation: 'Do not skip CSRF verification. If needed for API endpoints, use alternative protection like API tokens.',
            category:    'CSRF'
          )
        end
      end
    end

    # protect_from_forgery with: :null_session (may be intentional for APIs)
    if method_name == :protect_from_forgery
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :hash
          arg.children.each do |pair|
            next unless pair.is_a?(Parser::AST::Node) && pair.type == :pair
            key, val = pair.children
            if sym_or_str?(key, 'with') && sym_or_str?(val, 'null_session')
              add_vuln(node,
                title:       'CSRF Protection set to null_session',
                severity:    'Medium',
                confidence:  'Medium',
                cwe:         'CWE-352',
                owasp:       'A01:2021',
                remediation: 'Use protect_from_forgery with: :exception for web applications. :null_session is only appropriate for pure APIs.',
                category:    'CSRF'
              )
            end
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 10: Hardcoded Secrets
# ==========================================================================
class HardcodedSecretsChecker < ASTWalker
  SECRET_PATTERNS = %w[
    password passwd secret api_key apikey api_secret access_key
    secret_key private_key token auth_token secret_key_base
    encryption_key aws_access_key aws_secret database_password
    db_password master_key credentials_key signing_key
  ].freeze

  private

  def visit(node)
    case node.type
    when :send
      _, method_name, *args = *node
      # config.secret_key_base = "hardcoded"
      if method_name.to_s.end_with?('=')
        attr_name = method_name.to_s.chomp('=')
        if SECRET_PATTERNS.any? { |p| attr_name.include?(p) }
          args.each do |arg|
            if arg.is_a?(Parser::AST::Node) && arg.type == :str && arg.children[0].to_s.length > 3
              add_vuln(node,
                title:       "Hardcoded Secret: #{attr_name}",
                severity:    'High',
                confidence:  'High',
                cwe:         'CWE-798',
                owasp:       'A07:2021',
                remediation: "Move #{attr_name} to environment variables or Rails credentials. Use ENV['#{attr_name.upcase}'].",
                category:    'Hardcoded Secrets'
              )
            end
          end
        end
      end
    when :pair
      # Hash key: { password: "secret" }
      key, val = node.children
      key_name = case key&.type
                 when :sym then key.children[0].to_s
                 when :str then key.children[0].to_s
                 else nil
                 end
      if key_name && SECRET_PATTERNS.any? { |p| key_name.downcase.include?(p) }
        if val.is_a?(Parser::AST::Node) && val.type == :str && val.children[0].to_s.length > 3
          add_vuln(node,
            title:       "Hardcoded Secret in hash: #{key_name}",
            severity:    'High',
            confidence:  'High',
            cwe:         'CWE-798',
            owasp:       'A07:2021',
            remediation: "Move #{key_name} to environment variables or encrypted credentials.",
            category:    'Hardcoded Secrets'
          )
        end
      end
    when :lvasgn, :ivasgn, :cvasgn, :gvasgn
      var_name = node.children[0].to_s.delete('@$')
      if SECRET_PATTERNS.any? { |p| var_name.downcase.include?(p) }
        val = node.children[1]
        if val.is_a?(Parser::AST::Node) && val.type == :str && val.children[0].to_s.length > 3
          add_vuln(node,
            title:       "Hardcoded Secret in variable: #{var_name}",
            severity:    'High',
            confidence:  'High',
            cwe:         'CWE-798',
            owasp:       'A07:2021',
            remediation: "Move #{var_name} to environment variables. Use ENV['#{var_name.upcase}'].",
            category:    'Hardcoded Secrets'
          )
        end
      end
    when :casgn
      const_name = node.children[1].to_s
      if SECRET_PATTERNS.any? { |p| const_name.downcase.include?(p) }
        val = node.children[2]
        if val.is_a?(Parser::AST::Node) && val.type == :str && val.children[0].to_s.length > 3
          add_vuln(node,
            title:       "Hardcoded Secret in constant: #{const_name}",
            severity:    'High',
            confidence:  'High',
            cwe:         'CWE-798',
            owasp:       'A07:2021',
            remediation: "Move #{const_name} to environment variables.",
            category:    'Hardcoded Secrets'
          )
        end
      end
    end
  end
end

# ==========================================================================
# Category 11: Weak Cryptography
# ==========================================================================
class WeakCryptoChecker < ASTWalker
  WEAK_DIGESTS = %w[MD5 SHA1 MD4 MD2].freeze
  WEAK_CIPHERS = %w[DES RC4 RC2 Blowfish].freeze

  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, *args = *node
    recv_name = receiver_name(node)

    # Digest::MD5.hexdigest, Digest::SHA1.new
    if recv_name && WEAK_DIGESTS.any? { |d| recv_name.include?(d) }
      add_vuln(node,
        title:       "Weak Cryptographic Hash: #{recv_name}",
        severity:    'Medium',
        confidence:  'High',
        cwe:         'CWE-328',
        owasp:       'A02:2021',
        remediation: 'Use SHA-256 or SHA-3 via Digest::SHA256. For password hashing, use bcrypt or argon2.',
        category:    'Weak Cryptography'
      )
    end

    # OpenSSL::Cipher with weak algorithms
    if recv_name&.include?('Cipher') && method_name == :new
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :str
          cipher_name = arg.children[0].to_s
          if WEAK_CIPHERS.any? { |c| cipher_name.upcase.include?(c.upcase) }
            add_vuln(node,
              title:       "Weak Cipher Algorithm: #{cipher_name}",
              severity:    'High',
              confidence:  'High',
              cwe:         'CWE-327',
              owasp:       'A02:2021',
              remediation: 'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.',
              category:    'Weak Cryptography'
            )
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 12: Insecure Random
# ==========================================================================
class InsecureRandomChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, * = *node

    # rand() or Kernel.rand
    if method_name == :rand
      recv_name = receiver_name(node)
      if recv.nil? || recv_name == 'Kernel' || recv_name == 'Random'
        add_vuln(node,
          title:       'Insecure Random Number Generator (rand)',
          severity:    'Medium',
          confidence:  'Medium',
          cwe:         'CWE-330',
          owasp:       'A02:2021',
          remediation: 'Use SecureRandom.random_number, SecureRandom.hex, or SecureRandom.uuid for security-sensitive operations.',
          category:    'Insecure Random'
        )
      end
    end

    # Random.new
    if receiver_name(node) == 'Random' && method_name == :new
      add_vuln(node,
        title:       'Insecure Random via Random.new (predictable)',
        severity:    'Medium',
        confidence:  'Medium',
        cwe:         'CWE-330',
        owasp:       'A02:2021',
        remediation: 'Use SecureRandom for cryptographic operations. Random is predictable if seed is known.',
        category:    'Insecure Random'
      )
    end

    # srand with fixed seed
    if method_name == :srand
      add_vuln(node,
        title:       'Insecure Random via srand (seeds predictable RNG)',
        severity:    'Low',
        confidence:  'Low',
        cwe:         'CWE-330',
        owasp:       'A02:2021',
        remediation: 'Use SecureRandom instead of seeding rand. srand makes the sequence reproducible.',
        category:    'Insecure Random'
      )
    end
  end
end

# ==========================================================================
# Category 13: Rails-specific
# ==========================================================================
class RailsSpecificChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # redirect_to with user input (open redirect)
    if method_name == :redirect_to
      args.each do |arg|
        if TaintSources.any_child_tainted?(arg)
          add_vuln(node,
            title:       'Open Redirect via redirect_to with user input',
            severity:    'Medium',
            confidence:  'High',
            cwe:         'CWE-601',
            owasp:       'A01:2021',
            remediation: 'Validate redirect URLs against a whitelist. Use only_path: true or url_for with allowed hosts.',
            category:    'Open Redirect'
          )
        end
      end
    end

    # content_tag with raw user content
    if method_name == :content_tag
      if args.length >= 2 && TaintSources.any_child_tainted?(args[1])
        # Check if html_safe or raw is called on user data in content_tag
        add_vuln(node,
          title:       'Potential XSS in content_tag with user input',
          severity:    'Medium',
          confidence:  'Medium',
          cwe:         'CWE-79',
          owasp:       'A03:2021',
          remediation: 'Ensure content_tag input is properly escaped. Do not call html_safe on user content.',
          category:    'XSS'
        )
      end
    end

    # render with user-controlled template
    if method_name == :render
      args.each do |arg|
        if TaintSources.any_child_tainted?(arg)
          add_vuln(node,
            title:       'Server-Side Template Injection via render with user input',
            severity:    'Critical',
            confidence:  'High',
            cwe:         'CWE-1336',
            owasp:       'A03:2021',
            remediation: 'Never pass user input to render. Use a whitelist of allowed templates.',
            category:    'Template Injection'
          )
        end
      end
    end
  end
end

# ==========================================================================
# Category 14: Sinatra-specific
# ==========================================================================
class SinatraSpecificChecker < ASTWalker
  private

  def visit(node)
    case node.type
    when :send
      _, method_name, *args = *node

      # set :session_secret, "weak"
      if method_name == :set
        if args.length >= 2 && sym_or_str?(args[0], 'session_secret')
          val = args[1]
          if val.is_a?(Parser::AST::Node) && val.type == :str && val.children[0].to_s.length < 32
            add_vuln(node,
              title:       'Weak Sinatra Session Secret',
              severity:    'High',
              confidence:  'High',
              cwe:         'CWE-798',
              owasp:       'A02:2021',
              remediation: 'Use a cryptographically random session secret of at least 64 characters. Use SecureRandom.hex(64).',
              category:    'Session Issues'
            )
          end
        end
      end

      # erb with user input
      if method_name == :erb
        if args.any? { |a| TaintSources.any_child_tainted?(a) }
          add_vuln(node,
            title:       'Template Injection via erb with user input',
            severity:    'Critical',
            confidence:  'High',
            cwe:         'CWE-1336',
            owasp:       'A03:2021',
            remediation: 'Never pass user input directly to erb. Use template files with proper escaping.',
            category:    'Template Injection'
          )
        end
      end
    end
  end
end

# ==========================================================================
# Category 15: Open Redirect
# ==========================================================================
class OpenRedirectChecker < ASTWalker
  REDIRECT_METHODS = %i[redirect redirect_to redirect_back].freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    if REDIRECT_METHODS.include?(method_name)
      args.each do |arg|
        if TaintSources.any_child_tainted?(arg) || interpolation_with_taint?(arg)
          add_vuln(node,
            title:       "Open Redirect via #{method_name} with user-controlled URL",
            severity:    'Medium',
            confidence:  'High',
            cwe:         'CWE-601',
            owasp:       'A01:2021',
            remediation: 'Validate redirect destinations against a whitelist of allowed URLs/hosts. Never redirect to user-supplied URLs directly.',
            category:    'Open Redirect'
          )
        end
      end
    end
  end
end

# ==========================================================================
# Category 16: File Upload
# ==========================================================================
class FileUploadChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # mount_uploader without validating content type / extension
    if method_name == :mount_uploader || method_name == :mount_uploaders
      add_vuln(node,
        title:       'File Upload via CarrierWave - verify content type validation',
        severity:    'Medium',
        confidence:  'Low',
        cwe:         'CWE-434',
        owasp:       'A04:2021',
        remediation: 'Ensure the uploader defines extension_allowlist and content_type_allowlist methods.',
        category:    'File Upload'
      )
    end

    # has_one_attached / has_many_attached (Active Storage)
    if method_name == :has_one_attached || method_name == :has_many_attached
      add_vuln(node,
        title:       'Active Storage File Upload - verify content type validation',
        severity:    'Low',
        confidence:  'Low',
        cwe:         'CWE-434',
        owasp:       'A04:2021',
        remediation: 'Add content_type validation: validates :attachment, content_type: [\'image/png\', \'image/jpg\']',
        category:    'File Upload'
      )
    end
  end
end

# ==========================================================================
# Category 17: Information Disclosure
# ==========================================================================
class InfoDisclosureChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # render json: { error: e.message, backtrace: e.backtrace }
    if method_name == :render
      args.each do |arg|
        next unless arg.is_a?(Parser::AST::Node) && arg.type == :hash
        sends = collect_sends(arg)
        if sends.include?(:backtrace) || sends.include?(:message)
          add_vuln(node,
            title:       'Information Disclosure: exception details in response',
            severity:    'Medium',
            confidence:  'Medium',
            cwe:         'CWE-209',
            owasp:       'A04:2021',
            remediation: 'Never expose stack traces or exception messages to end users. Log them server-side and return generic error messages.',
            category:    'Information Disclosure'
          )
        end
      end
    end

    # rescue => e; render e.backtrace
    if method_name == :backtrace || method_name == :full_message
      # Check if we're inside a rescue
      add_vuln(node,
        title:       'Potential Information Disclosure via exception details',
        severity:    'Low',
        confidence:  'Low',
        cwe:         'CWE-209',
        owasp:       'A04:2021',
        remediation: 'Do not expose exception backtraces in responses. Log server-side only.',
        category:    'Information Disclosure'
      )
    end
  end
end

# ==========================================================================
# Category 18: Session Issues
# ==========================================================================
class SessionIssuesChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # config.session_store :cookie_store with weak settings
    if method_name == :session_store
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :hash
          arg.children.each do |pair|
            next unless pair.type == :pair
            key, val = pair.children
            # key: "secret" with short value
            if sym_or_str?(key, 'key') && val.is_a?(Parser::AST::Node) && val.type == :str
              session_key = val.children[0].to_s
              if session_key.length < 30 && !session_key.start_with?('_')
                add_vuln(node,
                  title:       'Weak Session Key Name',
                  severity:    'Low',
                  confidence:  'Low',
                  cwe:         'CWE-384',
                  owasp:       'A07:2021',
                  remediation: 'Use a descriptive session key name prefixed with underscore: _myapp_session',
                  category:    'Session Issues'
                )
              end
            end
          end
        end
      end
    end

    # session[:user_id] = ... without regenerating session ID
    if method_name == :[]= && node.children[0].is_a?(Parser::AST::Node)
      recv = node.children[0]
      if recv.type == :send
        _, recv_method, * = *recv
        if recv_method == :session
          key_node = args[0] rescue nil
          if sym_or_str?(key_node, 'user_id', 'admin', 'authenticated', 'logged_in')
            add_vuln(node,
              title:       'Session Fixation Risk: setting auth session without regeneration',
              severity:    'Medium',
              confidence:  'Low',
              cwe:         'CWE-384',
              owasp:       'A07:2021',
              remediation: 'Call reset_session before setting authentication session values to prevent session fixation.',
              category:    'Session Issues'
            )
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 19: Authentication Issues
# ==========================================================================
class AuthenticationChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # BCrypt cost too low
    if method_name == :cost=
      recv_name = receiver_name(node)
      if recv_name&.include?('BCrypt') || recv_name&.include?('Password')
        args.each do |arg|
          if arg.is_a?(Parser::AST::Node) && arg.type == :int && arg.children[0] < 10
            add_vuln(node,
              title:       "Weak BCrypt Cost Factor: #{arg.children[0]}",
              severity:    'Medium',
              confidence:  'High',
              cwe:         'CWE-916',
              owasp:       'A02:2021',
              remediation: 'Use a BCrypt cost factor of at least 12. Current OWASP recommendation is 12+.',
              category:    'Authentication'
            )
          end
        end
      end
    end

    # devise config: config.stretches = low_number
    if method_name == :stretches=
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :int && arg.children[0] < 10
          add_vuln(node,
            title:       "Weak Devise Stretches: #{arg.children[0]}",
            severity:    'Medium',
            confidence:  'High',
            cwe:         'CWE-916',
            owasp:       'A02:2021',
            remediation: 'Set Devise stretches to at least 12 for adequate password hashing security.',
            category:    'Authentication'
          )
        end
      end
    end

    # skip_before_action :authenticate_user!
    if %i[skip_before_action skip_before_filter].include?(method_name)
      args.each do |arg|
        if sym_or_str?(arg, 'authenticate_user!', 'authenticate!', 'require_login', 'login_required')
          add_vuln(node,
            title:       'Authentication Bypass: skipping authentication filter',
            severity:    'High',
            confidence:  'Medium',
            cwe:         'CWE-306',
            owasp:       'A07:2021',
            remediation: 'Avoid skipping authentication filters. If necessary, limit to specific actions with only: or except:.',
            category:    'Authentication'
          )
        end
      end
    end
  end
end

# ==========================================================================
# Category 20: Unsafe Reflection
# ==========================================================================
class UnsafeReflectionChecker < ASTWalker
  REFLECT_METHODS = %i[constantize safe_constantize const_get classify].freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    if REFLECT_METHODS.include?(method_name)
      recv = node.children[0]
      if recv && TaintSources.any_child_tainted?(recv)
        add_vuln(node,
          title:       "Unsafe Reflection via #{method_name} with user input",
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-470',
          owasp:       'A03:2021',
          remediation: "Never call #{method_name} on user input. Use a whitelist mapping: ALLOWED_CLASSES = {'type1' => Class1}",
          category:    'Unsafe Reflection'
        )
      elsif recv.is_a?(Parser::AST::Node) && recv.type == :dstr
        add_vuln(node,
          title:       "Potential Unsafe Reflection via #{method_name} with interpolation",
          severity:    'High',
          confidence:  'Medium',
          cwe:         'CWE-470',
          owasp:       'A03:2021',
          remediation: "Avoid calling #{method_name} on dynamically constructed strings. Use a whitelist.",
          category:    'Unsafe Reflection'
        )
      end
    end
  end
end

# ==========================================================================
# Category 21: Regex DoS
# ==========================================================================
class RegexDoSChecker < ASTWalker
  private

  def visit(node)
    case node.type
    when :regexp
      # Check for catastrophic backtracking patterns
      parts = node.children
      regex_str = parts.select { |c| c.is_a?(Parser::AST::Node) && c.type == :str }.map { |c| c.children[0] }.join
      if catastrophic_regex?(regex_str)
        add_vuln(node,
          title:       'Regular Expression Denial of Service (ReDoS)',
          severity:    'Medium',
          confidence:  'Medium',
          cwe:         'CWE-1333',
          owasp:       'A06:2021',
          remediation: 'Simplify the regular expression to avoid nested quantifiers. Use atomic groups or possessive quantifiers where supported.',
          category:    'Regex DoS'
        )
      end
    when :send
      _, method_name, *args = *node
      # Regexp.new(params[:pattern])
      if receiver_name(node) == 'Regexp' && method_name == :new
        if args.any? { |a| TaintSources.any_child_tainted?(a) }
          add_vuln(node,
            title:       'ReDoS via Regexp.new with user input',
            severity:    'High',
            confidence:  'High',
            cwe:         'CWE-1333',
            owasp:       'A06:2021',
            remediation: 'Never construct regular expressions from user input. Use Regexp.escape or a timeout.',
            category:    'Regex DoS'
          )
        end
      end
    end
  end

  def catastrophic_regex?(str)
    # Detect nested quantifiers like (a+)+, (a*)*  (\w+)+  etc.
    return true if str =~ /\([^)]*[+*][^)]*\)[+*]/
    # Overlapping alternation with quantifiers
    return true if str =~ /\([^)]*\|[^)]*\)[+*]/
    # Repeated groups with quantifiers
    return true if str =~ /\{[^}]*\}[+*]/
    false
  end
end

# ==========================================================================
# Category 22: Missing Authorization
# ==========================================================================
class MissingAuthorizationChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # skip_authorization, skip_authorize
    if %i[skip_authorization skip_authorize skip_authorization_check].include?(method_name)
      add_vuln(node,
        title:       'Authorization Check Skipped',
        severity:    'High',
        confidence:  'Medium',
        cwe:         'CWE-862',
        owasp:       'A01:2021',
        remediation: 'Do not skip authorization checks. If needed, limit scope with only: or except: options.',
        category:    'Missing Authorization'
      )
    end

    # CanCanCan: skip_load_and_authorize_resource
    if method_name == :skip_load_and_authorize_resource || method_name == :skip_authorize_resource
      add_vuln(node,
        title:       "Authorization Bypass via #{method_name}",
        severity:    'High',
        confidence:  'Medium',
        cwe:         'CWE-862',
        owasp:       'A01:2021',
        remediation: 'Avoid skipping authorization. Apply authorize! checks to specific actions if needed.',
        category:    'Missing Authorization'
      )
    end
  end
end

# ==========================================================================
# Category 23: Logging Sensitive Data
# ==========================================================================
class SensitiveLoggingChecker < ASTWalker
  SENSITIVE_NAMES = %w[password passwd secret token api_key credit_card ssn social_security cvv pin].freeze

  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, *args = *node

    # Rails.logger.info(params[:password]), logger.debug(password)
    if %i[info debug warn error fatal].include?(method_name)
      recv_chain = receiver_chain(recv) rescue ''
      if recv_chain.include?('logger') || recv_chain.include?('Logger')
        args.each do |arg|
          sends = collect_sends(arg)
          str_content = collect_strings(arg)
          if sends.any? { |s| SENSITIVE_NAMES.any? { |p| s.to_s.downcase.include?(p) } } ||
             str_content.any? { |s| SENSITIVE_NAMES.any? { |p| s.downcase.include?(p) } }
            add_vuln(node,
              title:       'Sensitive Data Logged',
              severity:    'Medium',
              confidence:  'Medium',
              cwe:         'CWE-532',
              owasp:       'A09:2021',
              remediation: 'Never log sensitive data like passwords, tokens, or API keys. Use filter_parameters in Rails.',
              category:    'Logging Sensitive Data'
            )
          end
        end
      end
    end

    # puts/print with sensitive data
    if %i[puts print p pp].include?(method_name) && recv.nil?
      args.each do |arg|
        sends = collect_sends(arg)
        if sends.any? { |s| SENSITIVE_NAMES.any? { |p| s.to_s.downcase.include?(p) } }
          add_vuln(node,
            title:       'Sensitive Data Logged via puts/print',
            severity:    'Low',
            confidence:  'Low',
            cwe:         'CWE-532',
            owasp:       'A09:2021',
            remediation: 'Remove debug output of sensitive data. Use proper logging with filtering.',
            category:    'Logging Sensitive Data'
          )
        end
      end
    end
  end

  def collect_strings(node)
    result = []
    return result unless node.is_a?(Parser::AST::Node)
    result << node.children[0].to_s if node.type == :str
    result << node.children[0].to_s if node.type == :sym
    node.children.each { |c| result.concat(collect_strings(c)) }
    result
  end
end

# ==========================================================================
# Category 24: Cookie Security
# ==========================================================================
class CookieSecurityChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # cookies[:foo] = { value: "bar", httponly: false }
    if method_name == :[]=
      recv = node.children[0]
      if recv.is_a?(Parser::AST::Node) && recv.type == :send && recv.children[1] == :cookies
        args.each do |arg|
          if arg.is_a?(Parser::AST::Node) && arg.type == :hash
            has_httponly = false
            has_secure = false
            arg.children.each do |pair|
              next unless pair.type == :pair
              key, val = pair.children
              has_httponly = true if sym_or_str?(key, 'httponly')
              has_secure = true if sym_or_str?(key, 'secure')
            end
            unless has_httponly
              add_vuln(node,
                title:       'Cookie Missing httponly Flag',
                severity:    'Low',
                confidence:  'Medium',
                cwe:         'CWE-1004',
                owasp:       'A05:2021',
                remediation: 'Set httponly: true on cookies to prevent JavaScript access.',
                category:    'Cookie Security'
              )
            end
            unless has_secure
              add_vuln(node,
                title:       'Cookie Missing secure Flag',
                severity:    'Low',
                confidence:  'Medium',
                cwe:         'CWE-614',
                owasp:       'A05:2021',
                remediation: 'Set secure: true on cookies to ensure they are only sent over HTTPS.',
                category:    'Cookie Security'
              )
            end
          end
        end
      end
    end

    # config.force_ssl = false
    if method_name == :force_ssl=
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :false
          add_vuln(node,
            title:       'SSL Not Forced (force_ssl = false)',
            severity:    'Medium',
            confidence:  'High',
            cwe:         'CWE-319',
            owasp:       'A02:2021',
            remediation: 'Set config.force_ssl = true in production to ensure all traffic uses HTTPS.',
            category:    'Cookie Security'
          )
        end
      end
    end
  end
end

# ==========================================================================
# Category 25: Timing Attacks
# ==========================================================================
class TimingAttackChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # token == params[:token]  or  secret == user_input
    if method_name == :==
      recv = node.children[0]
      other = args[0]
      if secret_variable?(recv) || secret_variable?(other)
        if TaintSources.any_child_tainted?(recv) || TaintSources.any_child_tainted?(other)
          add_vuln(node,
            title:       'Timing Attack in Secret Comparison',
            severity:    'Medium',
            confidence:  'High',
            cwe:         'CWE-208',
            owasp:       'A02:2021',
            remediation: 'Use ActiveSupport::SecurityUtils.secure_compare or Rack::Utils.secure_compare instead of == for secret comparison.',
            category:    'Timing Attack'
          )
        end
      end
    end

    # Also check for Rack::Utils.secure_compare (positive - but we flag == usage)
    if method_name == :== && recv_is_secret_like?(node)
      add_vuln(node,
        title:       'Potential Timing Attack: string comparison with ==',
        severity:    'Low',
        confidence:  'Low',
        cwe:         'CWE-208',
        owasp:       'A02:2021',
        remediation: 'If comparing secrets or tokens, use secure_compare instead of ==.',
        category:    'Timing Attack'
      )
    end
  end

  def secret_variable?(node)
    return false unless node.is_a?(Parser::AST::Node)
    name = case node.type
           when :lvar, :ivar then node.children[0].to_s
           when :send then node.children[1].to_s
           else ''
           end
    %w[token secret api_key password digest signature hmac].any? { |s| name.downcase.include?(s) }
  end

  def recv_is_secret_like?(node)
    recv = node.children[0]
    return false unless recv.is_a?(Parser::AST::Node)
    secret_variable?(recv)
  end
end

# ==========================================================================
# Category 26: Template Injection
# ==========================================================================
class TemplateInjectionChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, *args = *node
    recv_name = receiver_name(node)

    # ERB.new(user_input)
    if recv_name == 'ERB' && method_name == :new
      if args.any? { |a| TaintSources.any_child_tainted?(a) || interpolation_with_taint?(a) }
        add_vuln(node,
          title:       'Server-Side Template Injection via ERB.new with user input',
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-1336',
          owasp:       'A03:2021',
          remediation: 'Never pass user input to ERB.new. Use pre-defined templates with parameter substitution.',
          category:    'Template Injection'
        )
      end
    end

    # Slim::Template.new, Haml::Engine.new with user input
    if %w[Slim Haml Liquid].any? { |e| recv_name&.include?(e) } && method_name == :new
      if args.any? { |a| TaintSources.any_child_tainted?(a) }
        add_vuln(node,
          title:       "Template Injection via #{recv_name}.new with user input",
          severity:    'Critical',
          confidence:  'High',
          cwe:         'CWE-1336',
          owasp:       'A03:2021',
          remediation: 'Never pass user input to template engine constructors.',
          category:    'Template Injection'
        )
      end
    end
  end
end

# ==========================================================================
# Category 27: Dynamic Dispatch
# ==========================================================================
class DynamicDispatchChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # object.send(params[:method]) or object.public_send(params[:method])
    if %i[send public_send __send__].include?(method_name)
      if args.any? { |a| TaintSources.any_child_tainted?(a) }
        add_vuln(node,
          title:       "Unsafe Dynamic Dispatch via #{method_name} with user input",
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-470',
          owasp:       'A03:2021',
          remediation: "Never pass user input to #{method_name}. Use a whitelist: ALLOWED_METHODS.include?(method) && obj.public_send(method)",
          category:    'Dynamic Dispatch'
        )
      elsif args.first.is_a?(Parser::AST::Node) && args.first.type == :dstr
        add_vuln(node,
          title:       "Potential Unsafe Dynamic Dispatch via #{method_name} with interpolation",
          severity:    'Medium',
          confidence:  'Medium',
          cwe:         'CWE-470',
          owasp:       'A03:2021',
          remediation: "Avoid dynamic method names in #{method_name}. Use explicit method calls or a whitelist.",
          category:    'Dynamic Dispatch'
        )
      end
    end

    # method(params[:name]).call
    if method_name == :method
      if args.any? { |a| TaintSources.any_child_tainted?(a) }
        add_vuln(node,
          title:       'Unsafe Dynamic Dispatch via method() with user input',
          severity:    'High',
          confidence:  'High',
          cwe:         'CWE-470',
          owasp:       'A03:2021',
          remediation: 'Never pass user input to method(). Use a whitelist of allowed method names.',
          category:    'Dynamic Dispatch'
        )
      end
    end
  end
end

# ==========================================================================
# Category 28: Null Safety / NoMethodError patterns
# ==========================================================================
class NullSafetyChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, * = *node

    # find / find_by without nil check (common NoMethodError source)
    if %i[find find_by find_by_id first last].include?(method_name)
      parent = find_parent_context(node)
      if parent && !has_nil_check?(parent, node)
        # Only flag when chaining calls on the result
        # This is heuristic-based
      end
    end

    # Direct method calls on potentially nil returns that are chained
    # e.g., User.find_by(id: params[:id]).name without &.
    if recv.is_a?(Parser::AST::Node) && recv.type == :send
      _, recv_method, * = *recv
      if %i[find_by first last detect find].include?(recv_method)
        add_vuln(node,
          title:       "Potential NoMethodError: calling #{method_name} on possibly nil result of #{recv_method}",
          severity:    'Low',
          confidence:  'Low',
          cwe:         'CWE-476',
          owasp:       'A06:2021',
          remediation: "Use safe navigation operator (&.) or add a nil check: obj&.#{method_name} or obj.try(:#{method_name})",
          category:    'Null Safety'
        )
      end
    end
  end

  def find_parent_context(node)
    nil # Simplified - would need parent tracking
  end

  def has_nil_check?(parent, node)
    false # Simplified
  end
end

# ==========================================================================
# Category 29: Race Conditions
# ==========================================================================
class RaceConditionChecker < ASTWalker
  private

  def visit(node)
    case node.type
    when :send
      _, method_name, *args = *node

      # Thread.new with shared state access
      if receiver_name(node) == 'Thread' && method_name == :new
        block = args.find { |a| a.is_a?(Parser::AST::Node) && a.type == :block }
        if block.nil?
          # Check for block argument in the block form
          ivar_accesses = find_nodes(node, :ivasgn)
          gvar_accesses = find_nodes(node, :gvasgn)
          cvar_accesses = find_nodes(node, :cvasgn)
          if ivar_accesses.any? || gvar_accesses.any? || cvar_accesses.any?
            add_vuln(node,
              title:       'Race Condition: shared state modification in Thread',
              severity:    'Medium',
              confidence:  'Medium',
              cwe:         'CWE-362',
              owasp:       'A04:2021',
              remediation: 'Use Mutex, Monitor, or concurrent-ruby primitives to synchronize access to shared state in threads.',
              category:    'Race Condition'
            )
          end
        end
      end

      # check-then-act pattern: File.exist? followed by File.open
      if receiver_name(node) == 'File' && %i[exist? exists? file? directory?].include?(method_name)
        add_vuln(node,
          title:       'Potential TOCTOU Race Condition (File.exist? check-then-act)',
          severity:    'Low',
          confidence:  'Low',
          cwe:         'CWE-367',
          owasp:       'A04:2021',
          remediation: 'Avoid check-then-act patterns with files. Use File.open with appropriate flags and handle exceptions.',
          category:    'Race Condition'
        )
      end

    when :block
      # Thread.new { @shared = value }
      send_node = node.children[0]
      if send_node.is_a?(Parser::AST::Node) && send_node.type == :send
        if receiver_name(send_node) == 'Thread' && send_node.children[1] == :new
          body = node.children[2]
          ivars = find_nodes(body, :ivasgn)
          gvars = find_nodes(body, :gvasgn)
          cvars = find_nodes(body, :cvasgn)
          if ivars.any? || gvars.any? || cvars.any?
            add_vuln(node,
              title:       'Race Condition: shared state modification in Thread block',
              severity:    'Medium',
              confidence:  'Medium',
              cwe:         'CWE-362',
              owasp:       'A04:2021',
              remediation: 'Use Mutex, Monitor, or concurrent-ruby to synchronize shared state access.',
              category:    'Race Condition'
            )
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 30: File Permissions
# ==========================================================================
class FilePermissionsChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    recv, method_name, *args = *node
    recv_name = receiver_name(node)

    # File.chmod(0777, file), FileUtils.chmod(0777, file)
    if %w[File FileUtils].include?(recv_name) && %i[chmod chmod_R].include?(method_name)
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :int
          mode = arg.children[0]
          if mode & 0o002 != 0 # world-writable
            add_vuln(node,
              title:       "World-Writable File Permissions: #{format('0%o', mode)}",
              severity:    'High',
              confidence:  'High',
              cwe:         'CWE-732',
              owasp:       'A01:2021',
              remediation: 'Avoid world-writable permissions. Use restrictive permissions like 0600 or 0644.',
              category:    'File Permissions'
            )
          elsif mode & 0o020 != 0 # group-writable
            add_vuln(node,
              title:       "Group-Writable File Permissions: #{format('0%o', mode)}",
              severity:    'Medium',
              confidence:  'Medium',
              cwe:         'CWE-732',
              owasp:       'A01:2021',
              remediation: 'Consider more restrictive permissions. Use 0600 for sensitive files.',
              category:    'File Permissions'
            )
          end
        end
      end
    end

    # File.open with overly permissive mode
    if recv_name == 'File' && method_name == :open
      args.each do |arg|
        if arg.is_a?(Parser::AST::Node) && arg.type == :int
          mode = arg.children[0]
          if mode & 0o002 != 0
            add_vuln(node,
              title:       "World-Writable File Created: #{format('0%o', mode)}",
              severity:    'High',
              confidence:  'High',
              cwe:         'CWE-732',
              owasp:       'A01:2021',
              remediation: 'Use restrictive file permissions. 0600 for private files, 0644 for readable files.',
              category:    'File Permissions'
            )
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 31: HTTP Security Headers (bonus)
# ==========================================================================
class HTTPSecurityHeadersChecker < ASTWalker
  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # config.action_dispatch.default_headers with missing security headers
    if method_name == :default_headers=
      # Just flag to review
      add_vuln(node,
        title:       'Review HTTP Security Headers Configuration',
        severity:    'Low',
        confidence:  'Low',
        cwe:         'CWE-693',
        owasp:       'A05:2021',
        remediation: 'Ensure security headers are set: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security.',
        category:    'HTTP Security Headers'
      )
    end

    # response.headers['X-Frame-Options'] = 'ALLOWALL'
    if method_name == :[]= && args.length >= 2
      key_arg = args[0]
      val_arg = args[1]
      if key_arg.is_a?(Parser::AST::Node) && key_arg.type == :str
        header = key_arg.children[0].to_s
        if header.downcase == 'x-frame-options' && val_arg.is_a?(Parser::AST::Node) && val_arg.type == :str
          val = val_arg.children[0].to_s.upcase
          if val.include?('ALLOW')
            add_vuln(node,
              title:       'Weak X-Frame-Options Header (clickjacking risk)',
              severity:    'Medium',
              confidence:  'High',
              cwe:         'CWE-1021',
              owasp:       'A05:2021',
              remediation: 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.',
              category:    'HTTP Security Headers'
            )
          end
        end
      end
    end
  end
end

# ==========================================================================
# Category 32: Dangerous Send (method dispatch to dangerous methods)
# ==========================================================================
class DangerousMethodCallChecker < ASTWalker
  DANGEROUS_GEMS = {
    'Oj.load' => { cwe: 'CWE-502', title: 'Potentially Unsafe Oj.load (may instantiate objects)' },
  }.freeze

  private

  def visit(node)
    return unless node.type == :send
    _, method_name, *args = *node

    # binding.pry / byebug / debugger left in code
    if %i[pry byebug debugger].include?(method_name)
      add_vuln(node,
        title:       "Debug Breakpoint Left in Code: #{method_name}",
        severity:    'Low',
        confidence:  'High',
        cwe:         'CWE-489',
        owasp:       'A05:2021',
        remediation: "Remove #{method_name} before deploying to production.",
        category:    'Information Disclosure'
      )
    end

    # Kernel.sleep (potential DoS if user-controlled)
    if method_name == :sleep
      if args.any? { |a| TaintSources.any_child_tainted?(a) }
        add_vuln(node,
          title:       'Denial of Service via user-controlled sleep',
          severity:    'Medium',
          confidence:  'High',
          cwe:         'CWE-400',
          owasp:       'A06:2021',
          remediation: 'Never pass user input to sleep. Validate and cap sleep duration.',
          category:    'Denial of Service'
        )
      end
    end

    # Dangerous: Oj.load
    recv_name = receiver_name(node)
    key = "#{recv_name}.#{method_name}"
    if DANGEROUS_GEMS.key?(key)
      info = DANGEROUS_GEMS[key]
      add_vuln(node,
        title:       info[:title],
        severity:    'Medium',
        confidence:  'Medium',
        cwe:         info[:cwe],
        owasp:       'A08:2021',
        remediation: 'Use Oj.safe_load or Oj.load with mode: :strict to prevent object instantiation.',
        category:    'Deserialization'
      )
    end
  end
end

# ==========================================================================
# Master Scanner - orchestrates all checkers
# ==========================================================================
class RubySASTScanner
  CHECKERS = [
    SQLInjectionChecker,
    CommandInjectionChecker,
    CodeInjectionChecker,
    XSSChecker,
    PathTraversalChecker,
    DeserializationChecker,
    SSRFChecker,
    MassAssignmentChecker,
    CSRFChecker,
    HardcodedSecretsChecker,
    WeakCryptoChecker,
    InsecureRandomChecker,
    RailsSpecificChecker,
    SinatraSpecificChecker,
    OpenRedirectChecker,
    FileUploadChecker,
    InfoDisclosureChecker,
    SessionIssuesChecker,
    AuthenticationChecker,
    UnsafeReflectionChecker,
    RegexDoSChecker,
    MissingAuthorizationChecker,
    SensitiveLoggingChecker,
    CookieSecurityChecker,
    TimingAttackChecker,
    TemplateInjectionChecker,
    DynamicDispatchChecker,
    NullSafetyChecker,
    RaceConditionChecker,
    FilePermissionsChecker,
    HTTPSecurityHeadersChecker,
    DangerousMethodCallChecker,
  ].freeze

  def scan_files(files, scan_id)
    start_time = Time.now
    all_vulns = []
    files_scanned = 0
    parse_errors = []

    files.each do |path, content|
      next unless path.end_with?('.rb', '.rake', '.gemspec', 'Gemfile', 'Rakefile')
      begin
        buffer = Parser::Source::Buffer.new(path)
        buffer.source = content.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')
        parser = Parser::CurrentRuby.new
        parser.diagnostics.consumer = ->(_) {} # suppress parser warnings
        ast = parser.parse(buffer)

        next unless ast

        CHECKERS.each do |checker_class|
          checker = checker_class.new(path, content)
          checker.walk(ast)
          all_vulns.concat(checker.vulns)
        end

        files_scanned += 1
      rescue Parser::SyntaxError => e
        parse_errors << { file: path, error: e.message }
        SCANNER_LOG.warn("Parse error in #{path}: #{e.message}")
      rescue => e
        parse_errors << { file: path, error: "#{e.class}: #{e.message}" }
        SCANNER_LOG.error("Error scanning #{path}: #{e.class}: #{e.message}")
      end
    end

    elapsed = ((Time.now - start_time) * 1000).round

    {
      scanId:        scan_id,
      scanner:       'ruby',
      version:       '1.0.0',
      filesScanned:  files_scanned,
      totalFiles:    files.size,
      parseErrors:   parse_errors,
      vulnerabilities: all_vulns.map(&:to_h),
      summary:       build_summary(all_vulns),
      scanDuration:  elapsed,
      timestamp:     Time.now.utc.iso8601
    }
  end

  private

  def build_summary(vulns)
    by_severity = vulns.group_by(&:severity)
    by_category = vulns.group_by(&:category)
    {
      total:    vulns.size,
      critical: (by_severity['Critical'] || []).size,
      high:     (by_severity['High'] || []).size,
      medium:   (by_severity['Medium'] || []).size,
      low:      (by_severity['Low'] || []).size,
      info:     (by_severity['Info'] || []).size,
      categories: by_category.transform_values(&:size)
    }
  end
end

# ==========================================================================
# Sinatra HTTP Application
# ==========================================================================
class ScannerApp < Sinatra::Base
  configure do
    set :port, 9007
    set :bind, '0.0.0.0'
    set :server, :webrick
    set :logging, true
    set :show_exceptions, false
  end

  before do
    content_type :json
  end

  get '/health' do
    {
      status:  'healthy',
      scanner: 'ruby-sast',
      version: '1.0.0',
      port:    9007,
      uptime:  (Time.now - settings.start_time).round,
      ruby:    RUBY_VERSION,
      parser:  Parser::VERSION
    }.to_json
  end

  post '/scan' do
    begin
      body = request.body.read
      payload = JSON.parse(body)

      files   = payload['files'] || {}
      scan_id = payload['scanId'] || SecureRandom.uuid

      if files.empty?
        status 400
        return { error: 'No files provided', scanId: scan_id }.to_json
      end

      SCANNER_LOG.info("Scan #{scan_id}: #{files.size} files received")

      scanner = RubySASTScanner.new
      result  = scanner.scan_files(files, scan_id)

      SCANNER_LOG.info("Scan #{scan_id}: found #{result[:vulnerabilities].size} vulnerabilities in #{result[:filesScanned]} files (#{result[:scanDuration]}ms)")

      status 200
      result.to_json

    rescue JSON::ParserError => e
      status 400
      { error: "Invalid JSON: #{e.message}" }.to_json
    rescue => e
      SCANNER_LOG.error("Scan error: #{e.class}: #{e.message}\n#{e.backtrace&.first(5)&.join("\n")}")
      status 500
      { error: "Internal scanner error: #{e.message}" }.to_json
    end
  end

  # Catch-all
  not_found do
    { error: 'Not found', endpoints: ['GET /health', 'POST /scan'] }.to_json
  end

  set :start_time, Time.now
end

# ==========================================================================
# Main entry point
# ==========================================================================
if __FILE__ == $0
  SCANNER_LOG.info("Starting Ruby SAST Scanner on port 9007...")
  puts "Ruby SAST Scanner v1.0.0 starting on port 9007"
  puts "Ruby #{RUBY_VERSION} | Parser #{Parser::VERSION}"
  ScannerApp.run! port: 9007, bind: '0.0.0.0'
end
