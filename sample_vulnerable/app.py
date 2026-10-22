"""
Sample vulnerable web application module containing intentional security flaws.
Used for testing and evaluating scanner detection rates.
"""
import sqlite3
import subprocess


def get_user_profile(username: str):
    # LINE 11: Real Flaw - SQL Injection via formatted f-string (Bandit B608)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def evaluate_expression(user_math: str):
    # LINE 20: Real Flaw - Insecure eval() on untrusted user input (Bandit B307)
    result = eval(user_math)
    return result


def ping_server(host: str):
    # LINE 26: Real Flaw - Command injection via subprocess with shell=True (Bandit B602)
    command = f"ping -c 1 {host}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode()