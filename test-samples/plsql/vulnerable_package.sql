-- Offensive360 PL/SQL Test Sample - Vulnerable Package
-- This file contains intentional vulnerabilities for scanner testing

CREATE OR REPLACE PACKAGE BODY vulnerable_pkg AS

    -- PLSQL-SQLI-001: EXECUTE IMMEDIATE with concatenation
    PROCEDURE search_users(p_name IN VARCHAR2) IS
        v_sql VARCHAR2(4000);
    BEGIN
        v_sql := 'SELECT * FROM users WHERE name = ''' || p_name || '''';
        EXECUTE IMMEDIATE v_sql;
    END search_users;

    -- PLSQL-SQLI-002: DBMS_SQL with dynamic SQL
    PROCEDURE dynamic_query(p_table IN VARCHAR2, p_where IN VARCHAR2) IS
        v_cursor INTEGER;
        v_result INTEGER;
    BEGIN
        v_cursor := DBMS_SQL.OPEN_CURSOR;
        DBMS_SQL.PARSE(v_cursor, 'SELECT * FROM ' || p_table || ' WHERE ' || p_where, DBMS_SQL.NATIVE);
        v_result := DBMS_SQL.EXECUTE(v_cursor);
        DBMS_SQL.CLOSE_CURSOR(v_cursor);
    END dynamic_query;

    -- PLSQL-SQLI-003: Dynamic SQL via variable
    PROCEDURE run_dynamic(p_query IN VARCHAR2) IS
    BEGIN
        EXECUTE IMMEDIATE p_query;
    END run_dynamic;

    -- PLSQL-SQLI-004: OPEN cursor with concatenation
    PROCEDURE get_records(p_filter IN VARCHAR2) IS
        TYPE ref_cur IS REF CURSOR;
        v_cursor ref_cur;
        v_sql VARCHAR2(4000);
    BEGIN
        v_sql := 'SELECT id, name FROM employees WHERE dept = ''' || p_filter || '''';
        OPEN v_cursor FOR v_sql;
        CLOSE v_cursor;
    END get_records;

    -- PLSQL-PRIV-001: AUTHID CURRENT_USER with dynamic SQL
    -- (Shown at package level)

    -- PLSQL-PRIV-002: GRANT with ADMIN OPTION
    PROCEDURE setup_roles IS
    BEGIN
        EXECUTE IMMEDIATE 'GRANT DBA TO app_user WITH ADMIN OPTION';
    END setup_roles;

    -- PLSQL-CINJ-001: DBMS_SCHEDULER with user input
    PROCEDURE schedule_job(p_job_name IN VARCHAR2, p_action IN VARCHAR2) IS
    BEGIN
        DBMS_SCHEDULER.CREATE_JOB(
            job_name => p_job_name,
            job_action => 'BEGIN ' || p_action || '; END;',
            job_type => 'PLSQL_BLOCK'
        );
    END schedule_job;

    -- PLSQL-PATH-001: UTL_FILE with user-controlled path
    PROCEDURE read_file(p_dir IN VARCHAR2, p_filename IN VARCHAR2) IS
        v_file UTL_FILE.FILE_TYPE;
        v_line VARCHAR2(4000);
    BEGIN
        v_file := UTL_FILE.FOPEN(p_dir || '/subdir', p_filename, 'R');
        UTL_FILE.GET_LINE(v_file, v_line);
        UTL_FILE.FCLOSE(v_file);
    END read_file;

    -- PLSQL-INFO-001: DBMS_OUTPUT with sensitive data
    PROCEDURE debug_user(p_user_id IN NUMBER) IS
        v_password VARCHAR2(100);
    BEGIN
        SELECT password INTO v_password FROM users WHERE id = p_user_id;
        DBMS_OUTPUT.PUT_LINE('User password is: ' || v_password);
    END debug_user;

    -- PLSQL-INFO-002: Error message reveals schema
    PROCEDURE process_data(p_id IN NUMBER) IS
    BEGIN
        DELETE FROM sensitive_table WHERE id = p_id;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE_APPLICATION_ERROR(-20001, 'Error in SENSITIVE_TABLE: ' || SQLERRM);
    END process_data;

    -- PLSQL-CRED-001: Hardcoded password
    PROCEDURE connect_db IS
        v_conn VARCHAR2(200);
    BEGIN
        password := 'SuperSecret123!';
        v_conn := 'jdbc:oracle:thin:@host:1521:ORCL';
    END connect_db;

    -- PLSQL-CRED-003: Default password
    PROCEDURE create_user IS
    BEGIN
        EXECUTE IMMEDIATE 'CREATE USER test_user IDENTIFIED BY tiger';
    END create_user;

    -- PLSQL-CRYP-001: DBMS_OBFUSCATION_TOOLKIT (deprecated)
    PROCEDURE encrypt_data(p_data IN VARCHAR2) IS
        v_encrypted RAW(2000);
    BEGIN
        DBMS_OBFUSCATION_TOOLKIT.DES3ENCRYPT(
            input => UTL_RAW.CAST_TO_RAW(p_data),
            encrypted_data => v_encrypted
        );
    END encrypt_data;

    -- PLSQL-CRYP-002: DBMS_CRYPTO with weak algorithm
    PROCEDURE weak_encrypt(p_data IN RAW) IS
        v_key RAW(128) := UTL_RAW.CAST_TO_RAW('0123456789ABCDEF');
        v_encrypted RAW(2000);
    BEGIN
        v_encrypted := DBMS_CRYPTO.ENCRYPT_DES(
            src => p_data,
            key => v_key
        );
    END weak_encrypt;

    -- PLSQL-PRIV-003: DBA role grant
    PROCEDURE grant_admin IS
    BEGIN
        EXECUTE IMMEDIATE 'GRANT DBA TO new_developer';
    END grant_admin;

    -- PLSQL-PRIV-004: ANY privilege grant
    PROCEDURE grant_any IS
    BEGIN
        EXECUTE IMMEDIATE 'GRANT SELECT ANY TABLE TO reporting_user';
    END grant_any;

    -- PLSQL-PRIV-005: PUBLIC grant on sensitive package
    PROCEDURE grant_public IS
    BEGIN
        EXECUTE IMMEDIATE 'GRANT EXECUTE ON UTL_FILE TO PUBLIC';
        EXECUTE IMMEDIATE 'GRANT EXECUTE ON UTL_HTTP TO PUBLIC';
    END grant_public;

    -- PLSQL-SSRF-001: UTL_HTTP without validation
    PROCEDURE fetch_url(p_url IN VARCHAR2) IS
        v_response UTL_HTTP.HTML_PIECES;
    BEGIN
        v_response := UTL_HTTP.REQUEST(p_url);
    END fetch_url;

    -- PLSQL-SSRF-002: UTL_TCP connection
    PROCEDURE send_data(p_host IN VARCHAR2, p_port IN NUMBER) IS
        v_conn UTL_TCP.CONNECTION;
    BEGIN
        v_conn := UTL_TCP.OPEN_CONNECTION(p_host, p_port);
        UTL_TCP.CLOSE_CONNECTION(v_conn);
    END send_data;

    -- PLSQL-SSRF-003: UTL_SMTP
    PROCEDURE send_email(p_to IN VARCHAR2, p_body IN VARCHAR2) IS
        v_conn UTL_SMTP.CONNECTION;
    BEGIN
        v_conn := UTL_SMTP.OPEN_CONNECTION('mail.example.com', 25);
        UTL_SMTP.MAIL(v_conn, 'sender@example.com');
        UTL_SMTP.RCPT(v_conn, p_to);
        UTL_SMTP.DATA(v_conn, p_body);
    END send_email;

    -- PLSQL-XML-001: XMLTYPE with concatenation
    PROCEDURE parse_xml(p_input IN VARCHAR2) IS
        v_xml XMLTYPE;
    BEGIN
        v_xml := XMLTYPE('<root><data>' || p_input || '</data></root>');
    END parse_xml;

    -- PLSQL-DATA-001: SELECT * without column restriction
    PROCEDURE get_all_data IS
        CURSOR c IS SELECT * FROM employees;
    BEGIN
        NULL;
    END get_all_data;

    -- PLSQL-AUDIT-001: Sensitive operation without audit
    PROCEDURE update_salary(p_emp_id IN NUMBER, p_amount IN NUMBER) IS
    BEGIN
        UPDATE salaries SET amount = p_amount WHERE emp_id = p_emp_id;
        COMMIT;
    END update_salary;

    -- PLSQL-AUTO-001: AUTONOMOUS_TRANSACTION in trigger
    -- (Would be in a separate trigger definition)

    -- PLSQL-CRED-004: Hardcoded encryption key
    PROCEDURE encrypt_with_key IS
        encryption_key VARCHAR2(100) := 'MySecretAESKey12345678901234567890';
    BEGIN
        NULL;
    END encrypt_with_key;

    -- PLSQL-EXCP-001: WHEN OTHERS without re-raise
    PROCEDURE bad_exception_handler IS
    BEGIN
        NULL;
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('An error occurred');
    END bad_exception_handler;

    -- PLSQL-TBS-001: Objects in SYSTEM tablespace
    PROCEDURE create_objects IS
    BEGIN
        EXECUTE IMMEDIATE 'CREATE TABLE temp_data (id NUMBER) TABLESPACE SYSTEM';
    END create_objects;

    -- PLSQL-TNS-001: Listener config in source
    PROCEDURE get_connection IS
        v_tns VARCHAR2(500) := '(DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = prod-db.internal)(PORT = 1521))(CONNECT_DATA = (SERVICE_NAME = PRODDB)))';
    BEGIN
        NULL;
    END get_connection;

    -- PLSQL-CRYP-003: Missing encryption for sensitive data
    PROCEDURE store_credit_card IS
    BEGIN
        INSERT INTO customers (id, name, credit_card, ssn)
        VALUES (1, 'John Doe', '4111111111111111', '123-45-6789');
    END store_credit_card;

END vulnerable_pkg;
/

-- PLSQL-AUTO-001: Autonomous transaction in trigger
CREATE OR REPLACE TRIGGER trg_audit_bypass
BEFORE DELETE ON employees
FOR EACH ROW
DECLARE
    PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO audit_log (action, emp_id) VALUES ('DELETE', :OLD.id);
    COMMIT;
END;
/

-- PLSQL-PRIV-006: GRANT ALL PRIVILEGES
GRANT ALL PRIVILEGES TO developer_user;

-- Sensitive table operations
CREATE TABLE users (
    id NUMBER PRIMARY KEY,
    username VARCHAR2(100),
    password VARCHAR2(256),
    ssn VARCHAR2(20),
    credit_card VARCHAR2(30)
);

-- PLSQL-SQLI-005: Dynamic table name
PROCEDURE dynamic_table(p_table_name IN VARCHAR2) IS
BEGIN
    EXECUTE IMMEDIATE 'SELECT * FROM ' || p_table_name || ' WHERE 1=1';
END;
/
