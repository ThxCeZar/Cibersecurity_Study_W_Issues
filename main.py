# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
import os
from dotenv import load_dotenv
import bcrypt 
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_fallback_secret_key')

# Inicializar bcrypt
bcrypt_instance = bcrypt.Bcrypt(app) # Inicializamos bcrypt con la app de Flask

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

# Función para hashear contraseñas usando bcrypt
def hash_password(password):
    # Genera un salt y hashea la contraseña
    salt = bcrypt_instance.gensalt()
    hashed = bcrypt_instance.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8') # Devuelve como string para almacenar

# Función para verificar la contraseña
def check_password(password, hashed):
    # Compara la contraseña proporcionada con el hash almacenado
    return bcrypt_instance.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'] # Contraseña en texto plano desde el formulario

        try:
            # Obtiene el usuario de la base de datos
            response = supabase.table('users').select('*').eq('UserName', username).execute()
            user_data = response.data

            if user_data:
                # Accede al primer (y debería ser único) registro
                user_record = user_data[0]
                stored_hashed_password = user_record['UserPassword']

                # Verifica la contraseña usando bcrypt
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
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'] # Contraseña en texto plano desde el formulario
        hashed_password = hash_password(password) # Hashea la contraseña

        try:
            # Verificar si el nombre de usuario ya existe
            check_response = supabase.table('users').select('id').eq('UserName', username).execute()
            if check_response.data:
                flash('El nombre de usuario ya está en uso.')
            else:
                # Insertar nuevo usuario con la contraseña hasheada
                supabase.table('users').insert({
                    'UserName': username,
                    'UserPassword': hashed_password # Almacena el hash
                }).execute()
                flash('Usuario registrado exitosamente. Puedes iniciar sesión.')
                return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error al registrar usuario: {e}')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Has cerrado sesión.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # No uses debug=True en producción
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
