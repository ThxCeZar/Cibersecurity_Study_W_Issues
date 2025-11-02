# main.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
import os
from dotenv import load_dotenv
import bcrypt
from functools import wraps
from cryptography.fernet import Fernet # Importamos Fernet para cifrado/descifrado
import base64
from markupsafe import Markup # Importamos Markup

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_fallback_secret_key')

# Carga la clave de cifrado desde las variables de entorno
# Debes generar una clave con `Fernet.generate_key()` y guardarla en Render como variable de entorno
cipher_key = os.getenv('CIPHER_KEY')
if not cipher_key:
    print("Advertencia: CIPHER_KEY no encontrada. Generando una clave temporal (NO para producción).")
    cipher_key = Fernet.generate_key()
    print(f"Clave temporal generada: {cipher_key.decode()}")
    cipher_key = base64.urlsafe_b64decode(cipher_key)
else:
    # Asegúrate de que la clave esté en formato adecuado para Fernet
    cipher_key = base64.urlsafe_b64decode(cipher_key)
cipher_suite = Fernet(cipher_key)

url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Por favor, inicia sesión para acceder a los cursos.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

LEVELS = {
    'principiante': {
        'name': 'Principiante',
        'videos': [
            {'title': 'Principiante Video I', 'url': 'https://www.youtube.com/watch?v=principiante1'},
            {'title': 'Principiante Video II', 'url': 'https://www.youtube.com/watch?v=principiante2'},
            {'title': 'Principiante Video III', 'url': 'https://www.youtube.com/watch?v=principiante3'},
            {'title': 'Principiante Video IV', 'url': 'https://www.youtube.com/watch?v=principiante4'},
            {'title': 'Principiante Video V', 'url': 'https://www.youtube.com/watch?v=principiante5'},
        ]
    },
    'intermedio': {
        'name': 'Intermedio',
        'videos': [
            {'title': 'Intermedio Video I', 'url': 'https://www.youtube.com/watch?v=intermedio1'},
            {'title': 'Intermedio Video II', 'url': 'https://www.youtube.com/watch?v=intermedio2'},
            {'title': 'Intermedio Video III', 'url': 'https://www.youtube.com/watch?v=intermedio3'},
            {'title': 'Intermedio Video IV', 'url': 'https://www.youtube.com/watch?v=intermedio4'},
            {'title': 'Intermedio Video V', 'url': 'https://www.youtube.com/watch?v=intermedio5'},
        ]
    },
    'avanzado1': {
        'name': 'Avanzado I',
        'videos': [
            {'title': 'Avanzado I Video I', 'url': 'https://www.youtube.com/watch?v=avanzado1'},
            {'title': 'Avanzado I Video II', 'url': 'https://www.youtube.com/watch?v=avanzado2'},
            {'title': 'Avanzado I Video III', 'url': 'https://www.youtube.com/watch?v=avanzado3'},
            {'title': 'Avanzado I Video IV', 'url': 'https://www.youtube.com/watch?v=avanzado4'},
            {'title': 'Avanzado I Video V', 'url': 'https://www.youtube.com/watch?v=avanzado5'},
        ]
    },
    'avanzado2': {
        'name': 'Avanzado II',
        'videos': [
            {'title': 'Avanzado II Video I', 'url': 'https://www.youtube.com/watch?v=avanzado2_1'},
            {'title': 'Avanzado II Video II', 'url': 'https://www.youtube.com/watch?v=avanzado2_2'},
            {'title': 'Avanzado II Video III', 'url': 'https://www.youtube.com/watch?v=avanzado2_3'},
            {'title': 'Avanzado II Video IV', 'url': 'https://www.youtube.com/watch?v=avanzado2_4'},
            {'title': 'Avanzado II Video V', 'url': 'https://www.youtube.com/watch?v=avanzado2_5'},
        ]
    }
}

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_bytes.decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

@app.route('/')
def index():
    logged_in = 'username' in session
    return render_template('index.html', levels=LEVELS, logged_in=logged_in)

@app.route('/level/<level_name>')
@login_required
def show_level(level_name):
    if level_name not in LEVELS:
        return redirect(url_for('index'))
    level_info = LEVELS[level_name]
    logged_in = 'username' in session
    return render_template('level.html', level=level_info, level_key=level_name, logged_in=logged_in)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Pasamos la clave de cifrado a la plantilla, escapándola para JS
    cipher_key_js = Markup(cipher_key.decode()) if isinstance(cipher_key, bytes) else Markup(cipher_key)

    if request.method == 'POST':
        encrypted_username_b64 = request.form.get('username')
        encrypted_password_b64 = request.form.get('password')

        if not encrypted_username_b64 or not encrypted_password_b64:
            flash('Datos de formulario incompletos.')
            return render_template('login.html', cipher_key_js=cipher_key_js)

        try:
            username = cipher_suite.decrypt(encrypted_username_b64.encode()).decode()
            password = cipher_suite.decrypt(encrypted_password_b64.encode()).decode()
        except Exception as e:
            flash('Error al procesar los datos de inicio de sesión.')
            print(f"Error de descifrado: {e}")
            return render_template('login.html', cipher_key_js=cipher_key_js)

        try:
            response = supabase.table('users').select('*').eq('UserName', username).execute()
            user_data = response.data

            if user_data:
                user_record = user_data[0]
                stored_hashed_password = user_record['UserPassword']

                if check_password(password, stored_hashed_password):
                    session['username'] = username
                    flash('Inicio de sesión exitoso.')
                    return redirect(url_for('index'))
                else:
                    flash('Nombre de usuario o contraseña incorrectos.')
            else:
                flash('Nombre de usuario o contraseña incorrectos.')

        except Exception as e:
            flash(f'Error al conectar con la base de datos: {e}')
    return render_template('login.html', cipher_key_js=cipher_key_js)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Pasamos la clave de cifrado a la plantilla, escapándola para JS
    cipher_key_js = Markup(cipher_key.decode()) if isinstance(cipher_key, bytes) else Markup(cipher_key)

    if request.method == 'POST':
        encrypted_username_b64 = request.form.get('username')
        encrypted_password_b64 = request.form.get('password')

        if not encrypted_username_b64 or not encrypted_password_b64:
            flash('Datos de formulario incompletos.')
            return render_template('register.html', cipher_key_js=cipher_key_js)

        try:
            username = cipher_suite.decrypt(encrypted_username_b64.encode()).decode()
            password = cipher_suite.decrypt(encrypted_password_b64.encode()).decode()
        except Exception as e:
            flash('Error al procesar los datos de registro.')
            print(f"Error de descifrado: {e}")
            return render_template('register.html', cipher_key_js=cipher_key_js)

        hashed_password = hash_password(password)

        try:
            check_response = supabase.table('users').select('id').eq('UserName', username).execute()
            if check_response.data:
                flash('El nombre de usuario ya está en uso.')
            else:
                supabase.table('users').insert({
                    'UserName': username,
                    'UserPassword': hashed_password
                }).execute()
                flash('Usuario registrado exitosamente. Puedes iniciar sesión.')
                return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error al registrar usuario: {e}')
    return render_template('register.html', cipher_key_js=cipher_key_js)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Has cerrado sesión.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)