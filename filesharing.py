from flask import Flask, request, jsonify, send_file, session, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets

app = Flask(__name__)

# Configuration for Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration for JWT
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'your_mail_server'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_mail_username'
app.config['MAIL_PASSWORD'] = 'your_mail_password'
mail = Mail(app)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(60), unique=True)

# Define File model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)

# Registration endpoint with email verification
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = generate_password_hash(data.get('password'), method='sha256')

    new_user = User(email=email, password=password, verification_token=secrets.token_urlsafe(30))
    db.session.add(new_user)
    db.session.commit()

    # Send confirmation email
    send_verification_email(new_user)

    return jsonify(message='User registered successfully. Check your email for confirmation.')

# Email verification endpoint
@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()

    if user:
        user.confirmed = True
        user.verification_token = None
        db.session.commit()
        return jsonify(message='Email verified. You can now log in.')
    else:
        return jsonify(message='Invalid verification token.')

# Email confirmation helper function
def send_verification_email(user):
    token = user.verification_token
    verification_url = url_for('verify_email', token=token, _external=True)
    
    msg = Message('Verify Your Email', sender='your_email@example.com', recipients=[user.email])
    msg.body = f'Click the following link to verify your email: {verification_url}'
    mail.send(msg)

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = generate_password_hash(data.get('password'), method='sha256')

    new_user = User(email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    # Send confirmation email
    token = create_access_token(identity=email)
    confirmation_url = url_for('confirm_email', token=token, _external=True)
    send_confirmation_email=(email, confirmation_url)

    return jsonify(message='User registered successfully. Check your email for confirmation.')

# Email confirmation endpoint
@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    email = get_jwt_identity()
    current_user = User.query.filter_by(email=email).first()

    if not current_user.confirmed:
        current_user.confirmed = True
        db.session.commit()

    return jsonify(message='Email confirmed. You can now log in.')

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        if user.confirmed:
            session['user_id'] = user.id  # Store user ID in session
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token)
        else:
            return jsonify(message='Email not confirmed. Please check your email for confirmation link.')
    else:
        return jsonify(message='Invalid credentials. Please check your email and password.')

# File upload endpoint (only accessible by admin)
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = User.query.filter_by(email=get_jwt_identity()).first()

    if current_user.is_admin:
        if request.files:
            file = request.files['file']
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()

            return jsonify(message='File uploaded successfully.')
        else:
            return jsonify(message='No file provided.')
    else:
        return jsonify(message='Unauthorized. Only admin can upload files.')

# List all files for clients
@app.route('/files', methods=['GET'])
@login_required
def list_files():
    files = File.query.all()
    file_list = [{'id': file.id, 'filename': file.filename} for file in files]

    return jsonify(files=file_list)

# Logout endpoint
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # Remove user ID from session
    return jsonify(message='Logout successful.')

# File download endpoint (accessible by clients with the correct link and user in session)
@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    user_id_in_session = session.get('user_id')
    file = File.query.get(file_id)

    if user_id_in_session and file:
        # Assuming files are stored in the 'uploads' folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

        # Check if the file exists
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify(message='File not found.')
    else:
        return jsonify(message='Unauthorized. You do not have permission to download this file.')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
