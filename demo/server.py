# Simple Flask + SQLite demo for bsqli.py.
# 
# pip install flask
# python server.py
# 

from flask import Flask, request
import sqlite3
import random

app = Flask(__name__)

# In-memory SQLite database with dummy account information
conn = sqlite3.connect(':memory:', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
c.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpassword')")
c.execute('''CREATE TABLE flags (id INTEGER PRIMARY KEY, flag TEXT)''')
c.execute("INSERT INTO flags (flag) VALUES ('flag{SQL1nj3ct10n_aa9ce234d68}')")
conn.commit()

@app.route('/')
def index():
    return '''
    <h1>Welcome to the Boolean-based Blind SQL Injection Demo!</h1>
    <form method="post" action="/login">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    query = "SELECT * FROM users WHERE username='{}' AND password='{}'".format(username, password)
    c = conn.cursor()
    c.execute(query)
    user = c.fetchone()
    
    # Uncomment below lines to introduce a random error in the response.
    # if random.randint(0, 32) == 0:
    #     return 'Random error'

    if user:
        return 'Login successful!'
    else:
        return 'Login failed.'

if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    app.run(host, port, debug=True)
