import os
import subprocess
import sqlite3

# Pre-production server sample
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.dozG6pQGsptWyhMsnXdsqvWj4L-Pz_sample"

def get_user_profile(user_input):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerable to SQL Injection (CWE-89)
    query = f"SELECT id, username, email FROM accounts WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def run_diagnostic_ping(host):
    # Vulnerable to Command Injection (CWE-78)
    return subprocess.Popen(f"ping -c 1 {host}", shell=True)

if __name__ == "__main__":
    # Insecure network bind to all interfaces (CWE-1327)
    bind_host = "0.0.0.0"
    print(f"Starting developer server on {bind_host}:8080...")

