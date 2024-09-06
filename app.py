from flask import Flask, request, redirect, url_for, render_template, flash
import jwt
import datetime
import logging
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


app = Flask(__name__)
app.secret_key = 'key'

users = {
    'user': 'password',
    'user1': 'password1'
}
algorithm = "HS256"
logging.basicConfig(level=logging.DEBUG)
active_tokens = {}
#temp_data = {}
# Load RSA private key from file
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load RSA public key from file
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
#------------------------------------------------------------------------------------------------------------
#Functions for creating and validating access_tokens
def create_access_token(username):
    expiration = datetime.datetime.now() + datetime.timedelta(seconds=10)
    payload = {
        'username': username,
        'exp': expiration
    }
    token = jwt.encode(payload, app.secret_key, algorithm)
    
    # Encrypt the token using the RSA public key
    encrypted_token = public_key.encrypt(
        token.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    hashed_token = hashlib.sha256(encrypted_token).hexdigest()
    
    logging.debug(f"Generated token for {username}: {token}")
    logging.debug(f"Encrypted token: {encrypted_token}")
    logging.debug(f"Hashed token: {hashed_token}")
    
    active_tokens[username] = hashed_token
    logging.debug(f"Active tokens: {active_tokens}")
    return encrypted_token

def verify_token(encrypted_token):
    try:
        # Decrypt the token using the RSA private key
        decrypted_token = private_key.decrypt(
            encrypted_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hashed_token = hashlib.sha256(encrypted_token).hexdigest()
        
        username = next((user for user, h_token in active_tokens.items() if h_token == hashed_token), None)
        
        if not username:
            logging.debug("Token not found in active tokens.")
            return None

        payload = jwt.decode(decrypted_token, app.secret_key, algorithms=[algorithm])
        logging.debug(f"Token verified successfully: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logging.debug("Token has expired.")
        return None
    except jwt.InvalidTokenError:
        logging.debug("Invalid token.")
        return None
    except Exception as e:
        logging.debug(f"Token verification failed: {str(e)}")
        return None
#--------------------------------------------------------------------------------------------------------------
@app.route("/")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in active_tokens:
            flash("You are already logged in. Please logout from all other devices.")
            return render_template('login.html', username=username)
        if username in users and users[username] == password:
            token = create_access_token(username)
            #session['username'] = username  
            return redirect(url_for('dashboard', token=token.hex()))  # Convert bytes to hex string for URL
        else:
            flash("Invalid credentials")
            return render_template('login.html', username=username)
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    token_hex = request.args.get('token')
    if not token_hex:
        return redirect(url_for('login'))

    try:
        token_bytes = bytes.fromhex(token_hex)  # Convert hex string back to bytes
    except ValueError:
        return redirect(url_for('login'))

    payload = verify_token(token_bytes)
    if not payload:
        return redirect(url_for('logout'))

    unsaved_data = {}
    if request.method == 'POST':
        if 'submit' in request.form:
            logging.debug("Form submitted successfully!")
            return redirect(url_for('dashboard', token=token_hex))

    expiration = payload['exp'] * 1000

    return render_template('dashboard.html', username=payload['username'], token=token_hex, payload=payload, expiration=expiration, unsaved_data=unsaved_data)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    global active_tokens
    username = request.form.get('username')
    logging.debug(f"Logging out user: {username}")
    if username in active_tokens:
        del active_tokens[username]
        logging.debug(f"Active tokens after logout: {active_tokens}")
   
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/logout_all', methods=['POST'])
def logout_all():
    global active_tokens
    username = request.form.get('username')
    logging.debug(f"Logging out all devices for user: {username}")
    if username in active_tokens:
        del active_tokens[username]
        logging.debug(f"Active tokens after logout all: {active_tokens}")
   
    flash("You have been logged out from all devices.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

