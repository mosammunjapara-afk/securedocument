from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'system_super_key')

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user')''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_info (
                    id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, 
                    email TEXT, age INTEGER, status TEXT DEFAULT 'Pending',
                    FOREIGN KEY (user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

# --- NAVIGATION ROUTES ---
@app.route('/')
def index():
    return render_template('registration.html')

@app.route('/registration')
def registration():
    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        # Login action
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Check hardcoded roles
        if username == 'admin' and password == 'admin123':
            session['role'] = 'admin'
            return jsonify({'success': True, 'redirect': '/admin'})
        if username == 'supervisor' and password == 'supervisor456':
            session['role'] = 'supervisor'
            return jsonify({'success': True, 'redirect': '/supervisor'})
        if username == 'owner' and password == 'owner789':
            session['role'] = 'owner'
            return jsonify({'success': True, 'redirect': '/owner'})
        
        # DB check for user
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['role'] = 'user'
            return jsonify({'success': True, 'redirect': '/dashboard'})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    # GET: Render login page
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))  # Redirect to registration if not logged in
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# --- ACTION ROUTES ---
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password or len(password) < 6:
        return jsonify({'success': False, 'message': 'Invalid username or password (min 6 chars)'})
    
    hashed_pw = generate_password_hash(password)
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        return jsonify({'success': True, 'message': 'Registered!', 'redirect': '/login'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username already exists'})

@app.route('/fill_info', methods=['POST'])
def fill_info():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    data = request.json
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    age_str = data.get('age', '').strip()
    
    # Validate and convert age
    try:
        age = int(age_str)
        if age < 0 or age > 150:  # Basic range check
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid age (must be a number between 0-150)'})
    
    if not name or not email:
        return jsonify({'success': False, 'message': 'Name and email are required'})
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO user_info (user_id, name, email, age) VALUES (?, ?, ?, ?)",
                  (session['user_id'], name, email, age))
        conn.commit()
        return jsonify({'success': True, 'message': 'Information Submitted!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Submission failed'})

@app.route('/user_view', methods=['GET'])  # New: View user's own data
def user_view():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT name, email, age, status FROM user_info WHERE user_id=?", (session['user_id'],))
    data = c.fetchone()
    if data:
        return jsonify({'success': True, 'data': {'name': data[0], 'email': data[1], 'age': data[2], 'status': data[3]}})
    return jsonify({'success': False, 'message': 'No data submitted yet'})

# --- ADMIN ROUTES ---
@app.route('/admin')
def admin_panel():
    if session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    return render_template('admin.html')

@app.route('/admin_view', methods=['GET'])
def admin_view():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT ui.id, u.username, ui.name, ui.email, ui.age FROM user_info ui JOIN users u ON ui.user_id = u.id")
    data = c.fetchall()
    return jsonify({'data': [{'info_id': r[0], 'username': r[1], 'name': r[2], 'email': r[3], 'age': r[4]} for r in data]})

@app.route('/admin_edit', methods=['POST'])
def admin_edit():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    data = request.json
    info_id = data.get('info_id')
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    age_str = data.get('age', '').strip()
    try:
        age = int(age_str)
        if age < 0 or age > 150:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid age'})
    if not info_id or not name or not email:
        return jsonify({'success': False, 'message': 'Invalid data'})
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE user_info SET name=?, email=?, age=? WHERE id=?", (name, email, age, info_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Update failed'})

@app.route('/admin_delete', methods=['POST'])
def admin_delete():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    data = request.json
    info_id = data.get('info_id')
    if not info_id:
        return jsonify({'success': False, 'message': 'Invalid ID'})
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("DELETE FROM user_info WHERE id=?", (info_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Delete failed'})

# --- SUPERVISOR ROUTES ---
@app.route('/supervisor')
def supervisor_panel():
    if session.get('role') != 'supervisor':
        return redirect(url_for('login_page'))
    return render_template('supervisor.html')

@app.route('/supervisor_view', methods=['GET'])
def supervisor_view():
    if session.get('role') != 'supervisor':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT ui.id, u.username, ui.name, ui.email, ui.age FROM user_info ui JOIN users u ON ui.user_id = u.id")
    rows = c.fetchall()
    
    # Detect duplicates: check if name or email appears more than once
    names = [r[2] for r in rows]
    emails = [r[3] for r in rows]
    name_counts = {name: names.count(name) for name in set(names)}
    email_counts = {email: emails.count(email) for email in set(emails)}
    
    data = []
    for r in rows:
        is_duplicate = name_counts[r[2]] > 1 or email_counts[r[3]] > 1
        data.append({
            'info_id': r[0], 'username': r[1], 'name': r[2], 'email': r[3], 'age': r[4], 'is_duplicate': is_duplicate
        })
    return jsonify({'success': True, 'data': data})

@app.route('/supervisor_edit', methods=['POST'])
def supervisor_edit():
    if session.get('role') != 'supervisor':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    # Same as admin_edit
    return admin_edit()

@app.route('/supervisor_delete', methods=['POST'])
def supervisor_delete():
    if session.get('role') != 'supervisor':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    # Same as admin_delete
    return admin_delete()

# --- OWNER ROUTES ---
@app.route('/owner')
def owner_panel():
    if session.get('role') != 'owner':
        return redirect(url_for('login_page'))
    return render_template('owner.html')

@app.route('/owner_view', methods=['GET'])
def owner_view():
    if session.get('role') != 'owner':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT ui.id, ui.name, ui.email, ui.age, ui.status FROM user_info ui")
    data = c.fetchall()
    return jsonify({'success': True, 'data': [{'id': r[0], 'name': r[1], 'email': r[2], 'age': r[3], 'status': r[4]} for r in data]})

@app.route('/owner_approve', methods=['POST'])
def approve():
    if session.get('role') != 'owner':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    data = request.json
    info_id = data.get('info_id')
    if not info_id:
        return jsonify({'success': False, 'message': 'Invalid ID'})
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE user_info SET status='Approved' WHERE id=?", (info_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Approval failed'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)