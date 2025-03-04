from flask import Flask, render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
import re
import os
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for flash messages

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_keyed_alphabet(key1):
    """Generate a keyed alphabet with key letters first, followed by remaining letters."""
    seen = set()
    key_letters = []
    for char in key1.upper():
        if char.isalpha() and char not in seen:
            seen.add(char)
            key_letters.append(char)
    for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if char not in seen:
            key_letters.append(char)
    return ''.join(key_letters)

def generate_vigenere_table(keyed_alphabet):
    table = []
    for shift in range(26):
        row = [keyed_alphabet[(i + shift) % 26] for i in range(26)]
        table.append(row)
    return table

def vigenere_encrypt(plaintext, key, keyed_alphabet):
    encrypted = []
    highlights = []
    key = [k.upper() for k in key if k.isalpha()]
    if not key:
        return '', []
    
    key_indices = [ord(k) - ord('A') for k in key]
    
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            p = keyed_alphabet.index(char.upper())
            k = key_indices[key_index % len(key_indices)]
            c = (p + k) % 26
            encrypted_char = keyed_alphabet[c]
            if char.islower():
                encrypted_char = encrypted_char.lower()
            encrypted.append(encrypted_char)
            highlights.append((p, k))
            key_index += 1
        else:
            encrypted.append(char)
    
    return ''.join(encrypted), highlights

def vigenere_decrypt(ciphertext, key, keyed_alphabet):
    decrypted = []
    highlights = []
    key = [k.upper() for k in key if k.isalpha()]
    if not key:
        return '', []
    
    key_indices = [ord(k) - ord('A') for k in key]
    
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            c = keyed_alphabet.index(char.upper())
            k = key_indices[key_index % len(key_indices)]
            p = (c - k) % 26
            decrypted_char = keyed_alphabet[p]
            if char.islower():
                decrypted_char = decrypted_char.lower()
            decrypted.append(decrypted_char)
            highlights.append((c, k))
            key_index += 1
        else:
            decrypted.append(char)
    
    return ''.join(decrypted), highlights

def validate_input(text, key):
    errors = []
    if not text:
        errors.append("Text field cannot be empty")
    if not key:
        errors.append("Key cannot be empty")
    if not re.match("^[A-Za-z]*$", key):
        errors.append("Key must contain only letters")
    return errors

class History:
    HISTORY_FILE = 'cipher_history.json'

    def __init__(self):
        self.items = self.load_history()

    def add(self, operation, key, input_text, output_text):
        self.items.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'operation': operation,
            'key': key,
            'input': input_text,
            'output': output_text
        })
        self.save_history()

    def load_history(self):
        try:
            with open(self.HISTORY_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_history(self):
        with open(self.HISTORY_FILE, 'w') as f:
            json.dump(self.items, f)

history = History()

@app.route('/', methods=['GET', 'POST'])
def index():
    key1 = ''
    key2 = ''
    plaintext = ''
    ciphertext = ''
    encrypted = ''
    decrypted = ''
    table = []
    highlights = []
    keyed_alphabet = ''
    use_normal_table = False
    is_decryption = False  # Add this flag
    
    if request.method == 'POST':
        key1 = request.form.get('key1', '')
        key2 = request.form.get('key2', '')
        plaintext = request.form.get('plaintext', '')
        ciphertext = request.form.get('ciphertext', '')
        use_normal_table = 'use_normal_table' in request.form
        
        if 'encrypt' in request.form:
            errors = validate_input(plaintext, key1)
            if errors:
                for error in errors:
                    flash(error, 'error')
            else:
                if use_normal_table:
                    keyed_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                else:
                    keyed_alphabet = generate_keyed_alphabet(key2)
                table = generate_vigenere_table(keyed_alphabet)  # Generate table
                encrypted, highlights = vigenere_encrypt(plaintext, key1, keyed_alphabet)
                history.add('encrypt', key1, plaintext, encrypted)
        elif 'decrypt' in request.form:
            errors = validate_input(ciphertext, key1)
            if errors:
                for error in errors:
                    flash(error, 'error')
            else:
                if use_normal_table:
                    keyed_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                else:
                    keyed_alphabet = generate_keyed_alphabet(key2)
                table = generate_vigenere_table(keyed_alphabet)  # Generate table
                decrypted, highlights = vigenere_decrypt(ciphertext, key1, keyed_alphabet)
                history.add('decrypt', key1, ciphertext, decrypted)
                is_decryption = True  # Set flag for decryption
        elif 'upload' in request.form:
            file = request.files.get('file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                with open(filepath, 'r') as f:
                    content = f.read()
                os.remove(filepath)
                plaintext = content
                flash('File uploaded successfully', 'success')
            else:
                flash('Invalid file type or no file selected', 'error')
    
    # If no POST request, generate default table
    if not table:
        keyed_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        table = generate_vigenere_table(keyed_alphabet)

    return render_template('index.html', 
                           key1=key1,
                           key2=key2,
                           plaintext=plaintext,
                           ciphertext=ciphertext,
                           encrypted=encrypted,
                           decrypted=decrypted,
                           table=table,  # Always pass the table
                           highlights=highlights,
                           keyed_alphabet=keyed_alphabet,
                           use_normal_table=use_normal_table,
                           is_decryption=is_decryption,  # Pass the flag
                           history=history.items)  # Pass the history items directly

if __name__ == '__main__':
    app.run(debug=True)
