import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf import CSRFProtect
from wtforms import Form, StringField, PasswordField, HiddenField, validators

# Configuração básica do aplicativo
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'uma-chave-secreta-muito-segura-123'),
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', 'outra-chave-secreta-csrf-456'),
    DATABASE=os.path.join(app.instance_path, 'database.db'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurações
PAGBANK_LINKS = {
    'monthly': 'https://pag.ae/7_TnPtRxH',
    'yearly': 'https://pag.ae/7_TnQbYun'
}

ADMIN_CREDENTIALS = {
    'username': os.environ.get('ADMIN_USERNAME', 'admin'),
    'password': generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'senha-admin-secreta'))
}

# Formulários
class SubscriptionForm(Form):
    email = StringField('Email', validators=[
        validators.DataRequired(message="Email é obrigatório"),
        validators.Email(message="Email inválido"),
        validators.Length(min=6, max=50, message="Email deve ter entre 6 e 50 caracteres")
    ])
    password = PasswordField('Senha', validators=[
        validators.DataRequired(message="Senha é obrigatória"),
        validators.Length(min=6, message="Senha deve ter no mínimo 6 caracteres")
    ])
    subscription_type = HiddenField('Tipo de Assinatura', validators=[
        validators.DataRequired(message="Tipo de assinatura é obrigatório")
    ])

class LoginForm(Form):
    email = StringField('Email', validators=[
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField('Senha', validators=[
        validators.DataRequired()
    ])

# Database Helper
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def init_db():
    with app.app_context():
        os.makedirs(app.instance_path, exist_ok=True)
        db = get_db()
        try:
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
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    subscription_type TEXT NOT NULL,
                    payment_amount REAL NOT NULL,
                    payment_date TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    home_team TEXT NOT NULL,
                    away_team TEXT NOT NULL,
                    match_date TEXT NOT NULL,
                    match_time TEXT NOT NULL,
                    predicted_score TEXT,
                    home_win_percent INTEGER,
                    away_win_percent INTEGER,
                    draw_percent INTEGER,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            db.commit()
        except Exception as e:
            logger.error(f"Erro ao inicializar banco de dados: {e}")
            db.rollback()
        finally:
            db.close()

init_db()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Você precisa fazer login para acessar esta página', 'warning')
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_premium'):
            flash('Você precisa ser assinante premium para acessar este conteúdo', 'danger')
            return redirect(url_for('premium_subscription'))
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

# Rotas Públicas
@app.route('/')
def home():
    return redirect(url_for('premium_subscription'))

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    form = SubscriptionForm(request.form)
    
    if request.method == 'POST' and form.validate():
        db = None
        try:
            db = get_db()
            email = form.email.data.lower().strip()
            password = form.password.data
            subscription_type = form.subscription_type.data
            
            if subscription_type not in PAGBANK_LINKS:
                flash('Tipo de assinatura inválido', 'danger')
                return redirect(url_for('premium_subscription'))
            
            # Verifica se usuário já existe
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                if check_password_hash(user['password'], password):
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
            
            # Configura assinatura
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
            
            session['user_id'] = user_id
            session['logged_in'] = True
            session['is_premium'] = False
            
            return redirect(PAGBANK_LINKS[subscription_type])
            
        except sqlite3.IntegrityError:
            flash('Este email já está cadastrado', 'danger')
        except Exception as e:
            logger.error(f"Erro na assinatura: {e}")
            flash('Ocorreu um erro ao processar sua assinatura', 'danger')
        finally:
            if db:
                db.close()
    elif request.method == 'POST':
        flash('Por favor, corrija os erros no formulário', 'danger')
    
    return render_template('premium.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm(request.form)
    
    if request.method == 'POST' and form.validate():
        db = None
        try:
            db = get_db()
            email = form.email.data.lower().strip()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user and check_password_hash(user['password'], form.password.data):
                session['user_id'] = user['id']
                session['logged_in'] = True
                session['is_premium'] = bool(user['is_premium'])
                flash('Login realizado com sucesso!', 'success')
                
                if session['is_premium']:
                    return redirect(url_for('premium_matches'))
                return redirect(url_for('payment_verify'))
            else:
                flash('Email ou senha incorretos', 'danger')
        except Exception as e:
            logger.error(f"Erro no login: {e}")
            flash('Ocorreu um erro durante o login', 'danger')
        finally:
            if db:
                db.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado com sucesso', 'info')
    return redirect(url_for('home'))

@app.route('/payment/verify', methods=['GET', 'POST'])
def payment_verify():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Por favor, informe seu email', 'danger')
            return redirect(url_for('payment_verify'))
        
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
                
                if session.get('user_id') == user['id']:
                    session['is_premium'] = True
                
                flash('Pagamento verificado com sucesso! Acesso premium ativado.', 'success')
                return redirect(url_for('premium_matches'))
            else:
                flash('Nenhuma assinatura encontrada para este email', 'warning')
        except Exception as e:
            logger.error(f"Erro na verificação: {e}")
            flash('Ocorreu um erro ao verificar seu pagamento', 'danger')
        finally:
            if db:
                db.close()
    
    return render_template('payment_verify.html')

# Rotas Premium
@app.route('/premium/matches')
@login_required
@premium_required
def premium_matches():
    db = None
    try:
        db = get_db()
        today = datetime.now().strftime('%Y-%m-%d')
        matches = db.execute('''
            SELECT * FROM matches 
            WHERE match_date >= ?
            ORDER BY match_date ASC, match_time ASC
        ''', (today,)).fetchall()
        
        return render_template('premium_matches.html', matches=matches)
    except Exception as e:
        logger.error(f"Erro ao carregar partidas: {e}")
        flash('Ocorreu um erro ao carregar as partidas', 'danger')
        return redirect(url_for('home'))
    finally:
        if db:
            db.close()

# Rotas Admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    form = AdminLoginForm(request.form)
    
    if request.method == 'POST' and form.validate():
        username = form.username.data.strip()
        password = form.password.data
        
        if (username == ADMIN_CREDENTIALS['username'] and 
            check_password_hash(ADMIN_CREDENTIALS['password'], password)):
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
        users_count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        matches_count = db.execute('SELECT COUNT(*) FROM matches').fetchone()[0]
        return render_template('admin/dashboard.html', 
                             users_count=users_count, 
                             matches_count=matches_count)
    except Exception as e:
        logger.error(f"Erro no painel admin: {e}")
        flash('Ocorreu um erro no painel de administração', 'danger')
        return redirect(url_for('admin_login'))
    finally:
        if db:
            db.close()

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logout de administrador realizado', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)