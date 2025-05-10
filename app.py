from flask import Flask, render_template, request, redirect, url_for, session , flash
import mysql.connector
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# MySQL config
db = mysql.connector.connect(
    host=os.getenv('DB_HOST', 'myblog-sql.mysql.database.azure.com'),
    user=os.getenv('DB_USER', 'myadmin'),
    password=os.getenv('DB_PASSWORD', 'Yasu@100%'),
    database=os.getenv('DB_NAME', 'blog_database'),
    ssl_ca=os.getenv('DB_SSL_CA', 'DigiCertGlobalRootG2.crt.pem')
)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    cursor = db.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(id_=user[0], username=user[1])
    return None


#login and register

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Redirect if already logged in

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                           (username, email, password))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash('Error: ' + str(err), 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Redirect if already logged in

    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        cursor = db.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[1], password_input):
            user_obj = User(id_=user[0], username=username)
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

## Post  and comments
@app.route('/')
def home():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY created_at DESC")
    posts = cursor.fetchall()
    return render_template('home.html', posts=posts)

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    cursor = db.cursor(dictionary=True)
    if request.method == 'POST':
        if current_user.is_authenticated:
            content = request.form['comment']
            cursor.execute("INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)",
                           (post_id, current_user.id, content))
            db.commit()
        else:
            flash('You must be logged in to comment.', 'danger')

    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()

    cursor.execute("SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = %s ORDER BY created_at DESC", (post_id,))
    comments = cursor.fetchall()

    return render_template('post_detail.html', post=post, comments=comments)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        cursor = db.cursor()
        cursor.execute("INSERT INTO posts (user_id, title, content) VALUES (%s, %s, %s)",
                       (current_user.id, title, content))
        db.commit()
        return redirect(url_for('home'))
    return render_template('create_post.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)

