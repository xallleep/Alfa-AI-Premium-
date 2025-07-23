import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf import CSRFProtect
from wtforms import Form, StringField, PasswordField, HiddenField, validators

# Configuração básica do Flask
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-123456'),
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', 'csrf-dev-key-123456'),
    DATABASE=os.path.join(app.instance_path, 'matches.db'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

csrf = CSRFProtect(app)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Links de pagamento
PAGBANK_LINKS = {
    'monthly': 'https://pag.ae/7_TnPtRxH',
    'yearly': 'https://pag.ae/7_TnQbYun'
}

# Configurações de administrador
ADMIN_CREDENTIALS = {
    'username': os.environ.get('ADMIN_USERNAME', 'admin'),
    'password_hash': generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
}

# Classes de formulário
class SubscriptionForm(Form):
    email = StringField('Email', [
        validators.DataRequired(),
        validators.Email(),
        validators.Length(min=6, max=50)
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=6)
    ])
    subscription_type = HiddenField('Subscription Type', [
        validators.DataRequired()
    ])

class LoginForm(Form):
    email = StringField('Email', [
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])

class AdminLoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired()
    ])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])

# Funções de banco de dados
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    return db

def init_db():
    with app.app_context():
        os.makedirs(app.instance_path, exist_ok=True)
        db = get_db()
        try:
            # Tabela de usuários
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    is_premium BOOLEAN DEFAULT 0,
                    premium_expiry TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de assinaturas
            db.execute('''
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    subscription_type TEXT NOT NULL,
                    payment_amount REAL NOT NULL,
                    payment_date TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            # Tabela de partidas
            db.execute('''
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    home_team TEXT NOT NULL,
                    away_team TEXT NOT NULL,
                    competition TEXT,
                    match_date TEXT NOT NULL,
                    match_time TEXT NOT NULL,
                    predicted_score TEXT,
                    home_win_percent INTEGER DEFAULT 0,
                    away_win_percent INTEGER DEFAULT 0,
                    draw_percent INTEGER DEFAULT 0,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            db.commit()
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            db.rollback()
        finally:
            db.close()

init_db()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Por favor, faça login para acessar esta página', 'danger')
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Acesso restrito a administradores', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Rotas públicas
@app.route('/')
def index():
    return redirect(url_for('premium_subscription'))

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    form = SubscriptionForm(request.form)
    
    if request.method == 'POST' and form.validate():
        db = None
        try:
            db = get_db()
            email = form.email.data
            password = form.password.data
            subscription_type = form.subscription_type.data
            
            # Verifica se o usuário já existe
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                if check_password_hash(user['password'], password):
                    # Login bem-sucedido
                    session['user_id'] = user['id']
                    session['logged_in'] = True
                    session['is_premium'] = bool(user['is_premium'])
                    return redirect(PAGBANK_LINKS[subscription_type])
                else:
                    flash('Senha incorreta', 'danger')
                    return redirect(url_for('user_login'))
            
            # Cria novo usuário
            hashed_pw = generate_password_hash(password)
            db.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_pw))
            user_id = db.lastrowid
            
            # Configura a assinatura
            payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if subscription_type == 'monthly':
                expiry_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
                amount = 6.99
            else:
                expiry_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
                amount = 80.99
            
            db.execute('''
                INSERT INTO subscriptions 
                (user_id, subscription_type, payment_amount, payment_date, expiry_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, subscription_type, amount, payment_date, expiry_date))
            
            db.commit()
            
            # Configura a sessão
            session['user_id'] = user_id
            session['logged_in'] = True
            session['is_premium'] = False
            
            return redirect(PAGBANK_LINKS[subscription_type])
            
        except Exception as e:
            if db:
                db.rollback()
            logger.error(f"Subscription error: {e}")
            flash('Ocorreu um erro ao processar sua assinatura. Por favor, tente novamente.', 'danger')
        finally:
            if db:
                db.close()
    
    return render_template('premium.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm(request.form)
    
    if request.method == 'POST' and form.validate():
        db = None
        try:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email = ?', (form.email.data,)).fetchone()
            
            if user and check_password_hash(user['password'], form.password.data):
                session['user_id'] = user['id']
                session['logged_in'] = True
                session['is_premium'] = bool(user['is_premium'])
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('premium_matches'))
            else:
                flash('Email ou senha incorretos', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Ocorreu um erro durante o login', 'danger')
        finally:
            if db:
                db.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('index'))

# Rotas de administração
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm(request.form)
    
    if request.method == 'POST' and form.validate():
        if (form.username.data == ADMIN_CREDENTIALS['username'] and 
            check_password_hash(ADMIN_CREDENTIALS['password_hash'], form.password.data)):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Credenciais de administrador inválidas', 'danger')
    
    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = None
    try:
        db = get_db()
        matches = db.execute('SELECT * FROM matches ORDER BY match_date DESC').fetchall()
        users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
        return render_template('admin/dashboard.html', matches=matches, users=users)
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash('Erro ao carregar o painel de administração', 'danger')
        return redirect(url_for('admin_login'))
    finally:
        if db:
            db.close()

# ... (adicionar outras rotas de admin conforme necessário)

# Rotas de pagamento
@app.route('/payment/verify', methods=['GET', 'POST'])
def payment_verify():
    if request.method == 'POST':
        email = request.form.get('email')
        db = None
        try:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if not user:
                flash('Email não encontrado', 'danger')
                return redirect(url_for('payment_verify'))
            
            subscription = db.execute('''
                SELECT * FROM subscriptions 
                WHERE user_id = ? 
                ORDER BY payment_date DESC 
                LIMIT 1
            ''', (user['id'],)).fetchone()
            
            if subscription:
                db.execute('''
                    UPDATE users SET 
                        is_premium = 1,
                        premium_expiry = ?
                    WHERE id = ?
                ''', (subscription['expiry_date'], user['id']))
                
                db.execute('''
                    UPDATE subscriptions SET 
                        is_active = 1
                    WHERE id = ?
                ''', (subscription['id'],))
                
                db.commit()
                session['is_premium'] = True
                flash('Pagamento verificado com sucesso! Acesso premium ativado.', 'success')
                return redirect(url_for('premium_matches'))
            else:
                flash('Nenhuma assinatura encontrada para este email', 'warning')
        except Exception as e:
            if db:
                db.rollback()
            logger.error(f"Payment verification error: {e}")
            flash('Erro ao verificar pagamento', 'danger')
        finally:
            if db:
                db.close()
    
    return render_template('payment_verify.html')

# Rotas de conteúdo premium
@app.route('/premium/matches')
@login_required
def premium_matches():
    if not session.get('is_premium'):
        flash('Você precisa ser assinante premium para acessar este conteúdo', 'warning')
        return redirect(url_for('premium_subscription'))
    
    db = None
    try:
        db = get_db()
        matches = db.execute('''
            SELECT * FROM matches 
            WHERE match_date >= date('now') 
            ORDER BY match_date ASC
        ''').fetchall()
        return render_template('premium_matches.html', matches=matches)
    except Exception as e:
        logger.error(f"Matches error: {e}")
        flash('Erro ao carregar as partidas', 'danger')
        return redirect(url_for('index'))
    finally:
        if db:
            db.close()

# Inicialização
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)