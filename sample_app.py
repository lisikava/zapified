from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'weak-secret-key'  # Intentionally weak for testing

# Initialize database
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'userpass', 'user@test.com')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Vulnerable Test Application</h1>
    <p>This is a sample application with intentional vulnerabilities for security testing.</p>
    <ul>
        <li><a href="/search">Search (SQL Injection vulnerability)</a></li>
        <li><a href="/reflect">Reflect Input (XSS vulnerability)</a></li>
        <li><a href="/login">Login Page</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/file">File Operations</a></li>
    </ul>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        # Intentionally vulnerable SQL query for testing
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        try:
            # SQL Injection vulnerability
            sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
            cursor.execute(sql)
            results = cursor.fetchall()
            conn.close()
            
            response = f"<h2>Search Results for: {query}</h2><ul>"
            for user in results:
                response += f"<li>User: {user[1]}, Email: {user[3]}</li>"
            response += "</ul>"
            return response + '<br><a href="/">Back to Home</a>'
        except Exception as e:
            conn.close()
            return f"Error: {str(e)}<br><a href='/'>Back to Home</a>"
    
    return '''
    <h2>Search Users</h2>
    <form method="GET">
        <input type="text" name="q" placeholder="Search username...">
        <input type="submit" value="Search">
    </form>
    <br><a href="/">Back to Home</a>
    '''

@app.route('/reflect')
def reflect():
    user_input = request.args.get('input', '')
    if user_input:
        # XSS vulnerability - directly reflecting user input
        template = f'''
        <h2>Your input was:</h2>
        <div>{user_input}</div>
        <br><a href="/reflect">Try again</a> | <a href="/">Back to Home</a>
        '''
        return render_template_string(template)
    
    return '''
    <h2>Reflect Your Input</h2>
    <form method="GET">
        <input type="text" name="input" placeholder="Enter some text...">
        <input type="submit" value="Submit">
    </form>
    <br><a href="/">Back to Home</a>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Weak authentication logic
        if username and password:
            session['logged_in'] = True
            session['username'] = username
            return redirect('/admin')
    
    return '''
    <h2>Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <input type="submit" value="Login">
    </form>
    <br><a href="/">Back to Home</a>
    '''

@app.route('/admin')
def admin():
    # Weak access control
    if not session.get('logged_in'):
        return redirect('/login')
    
    return f'''
    <h2>Admin Panel</h2>
    <p>Welcome, {session.get('username', 'Unknown')}!</p>
    <p>This is a protected area with sensitive information.</p>
    <ul>
        <li>Server: {request.environ.get('SERVER_SOFTWARE', 'Unknown')}</li>
        <li>Python Version: {os.sys.version}</li>
        <li>Current Directory: {os.getcwd()}</li>
    </ul>
    <a href="/logout">Logout</a> | <a href="/">Back to Home</a>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/file')
def file_operations():
    filename = request.args.get('file')
    if filename:
        try:
            # Path traversal vulnerability
            with open(filename, 'r') as f:
                content = f.read()
            return f'<h2>File Content:</h2><pre>{content}</pre><br><a href="/file">Back</a>'
        except Exception as e:
            return f'Error reading file: {str(e)}<br><a href="/file">Back</a>'
    
    return '''
    <h2>File Reader</h2>
    <form method="GET">
        <input type="text" name="file" placeholder="Enter filename (e.g., test.txt)">
        <input type="submit" value="Read File">
    </form>
    <br><a href="/">Back to Home</a>
    '''

@app.route('/headers')
def show_headers():
    # Information disclosure
    headers_html = "<h2>Request Headers:</h2><ul>"
    for header, value in request.headers:
        headers_html += f"<li><strong>{header}:</strong> {value}</li>"
    headers_html += "</ul><br><a href='/'>Back to Home</a>"
    return headers_html

if __name__ == '__main__':
    init_db()
    print("Starting vulnerable test application...")
    print("This app contains intentional security vulnerabilities for testing purposes.")
    print("Do not use in production!")
    app.run(host='0.0.0.0', port=5000, debug=True)