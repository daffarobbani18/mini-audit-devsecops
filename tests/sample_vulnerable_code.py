"""
Sample Vulnerable Code
======================

This file contains INTENTIONALLY VULNERABLE code for testing purposes.
DO NOT USE this code in production!

These examples demonstrate various security issues that Bandit should detect.
"""

import os
import pickle
import subprocess
import hashlib
import random

# =============================================================================
# B101: assert_used - Using assert in production code
# =============================================================================
def check_admin(user):
    """Bad: Using assert for security check."""
    assert user.is_admin, "User must be admin"  # VULNERABLE: B101
    return True


# =============================================================================
# B102: exec_used - Use of exec
# =============================================================================
def execute_code(code_string):
    """Bad: Using exec to run arbitrary code."""
    exec(code_string)  # VULNERABLE: B102


# =============================================================================
# B105: hardcoded_password_string - Hardcoded password
# =============================================================================
def connect_database():
    """Bad: Hardcoded password in source code."""
    password = "SuperSecret123!"  # VULNERABLE: B105
    connection_string = f"postgresql://admin:{password}@localhost/db"
    return connection_string


# =============================================================================
# B106: hardcoded_password_funcarg - Password as function argument
# =============================================================================
def login(username, password="default_password"):  # VULNERABLE: B106
    """Bad: Default password in function argument."""
    return authenticate(username, password)


def authenticate(username, password):
    """Dummy authenticate function."""
    return True


# =============================================================================
# B108: hardcoded_tmp_directory - Hardcoded temp directory
# =============================================================================
def save_temp_file(data):
    """Bad: Using hardcoded /tmp path."""
    filepath = "/tmp/sensitive_data.txt"  # VULNERABLE: B108
    with open(filepath, "w") as f:
        f.write(data)


# =============================================================================
# B301: pickle - Using pickle (deserialization vulnerability)
# =============================================================================
def load_user_data(data_bytes):
    """Bad: Using pickle to deserialize untrusted data."""
    return pickle.loads(data_bytes)  # VULNERABLE: B301


# =============================================================================
# B303: md5/sha1 - Using weak hash algorithms
# =============================================================================
def hash_password_weak(password):
    """Bad: Using MD5 for password hashing."""
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: B303


def hash_data_sha1(data):
    """Bad: Using SHA1 which is cryptographically weak."""
    return hashlib.sha1(data.encode()).hexdigest()  # VULNERABLE: B303


# =============================================================================
# B307: eval - Use of eval
# =============================================================================
def calculate(expression):
    """Bad: Using eval to evaluate user input."""
    return eval(expression)  # VULNERABLE: B307


# =============================================================================
# B311: random - Using random for security purposes
# =============================================================================
def generate_token():
    """Bad: Using random instead of secrets for token generation."""
    token = "".join(
        random.choice("abcdefghijklmnopqrstuvwxyz0123456789")  # VULNERABLE: B311
        for _ in range(32)
    )
    return token


# =============================================================================
# B602: subprocess_popen_with_shell_equals_true - Shell injection
# =============================================================================
def run_command_unsafe(user_input):
    """Bad: Using shell=True with user input (command injection)."""
    subprocess.Popen(f"echo {user_input}", shell=True)  # VULNERABLE: B602


# =============================================================================
# B608: hardcoded_sql_expressions - SQL injection
# =============================================================================
def get_user_unsafe(username):
    """Bad: SQL injection vulnerability."""
    query = f"SELECT * FROM users WHERE username = '{username}'"  # VULNERABLE: B608
    return query


# =============================================================================
# B104: hardcoded_bind_all_interfaces - Binding to 0.0.0.0
# =============================================================================
def start_server():
    """Bad: Binding to all interfaces."""
    import socket
    s = socket.socket()
    s.bind(("0.0.0.0", 8080))  # VULNERABLE: B104
    return s


# =============================================================================
# For contrast: SECURE examples
# =============================================================================
import secrets
import subprocess as sp
from hashlib import sha256


def hash_password_secure(password):
    """Good: Using SHA-256 (though bcrypt/argon2 recommended for passwords)."""
    return sha256(password.encode()).hexdigest()


def generate_token_secure():
    """Good: Using secrets module for token generation."""
    return secrets.token_hex(32)


def run_command_safe(filename):
    """Good: Using subprocess without shell."""
    result = sp.run(["cat", filename], capture_output=True, text=True)
    return result.stdout


def get_user_safe(cursor, username):
    """Good: Using parameterized queries."""
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()
