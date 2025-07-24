import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Email, ValidationError
import json
from bleach import clean

# Configuração inicial do app
app = Flask(__name__)

# Configurações otimizadas para o Render Free Tier
app.config.update(
    SECRET_KEY=os.environ['SECRET_KEY'],  # Obrigatório - definir no Render
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ['CSRF_SECRET_KEY'],  # Obrigatório - definir no Render
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    TEMPLATES_AUTO_RELOAD=True,
    DATABASE=os.path.join(app.instance_path, 'matches.db'),
    # Configurações de rate limiting básico
    RATELIMIT_STORAGE_URI='memory://',
    # Configurações de logging
    LOG_LEVEL=logging.INFO
)

# Proteção CSRF
csrf = CSRFProtect(app)

# Links de pagamento (substitua pelos seus links reais)
PAGBANK_LINKS = {
    'monthly': 'https://pag.ae/7_TnPtRxH',
    'yearly': 'https://pag.ae/7_TnQbYun'
}

# Constantes
ADMIN_USERNAME = os.environ['ADMIN_USERNAME']  # Obrigatório - definir no Render
ADMIN_PASSWORD_HASH = generate_password_hash(os.environ['ADMIN_PASSWORD'])  # Obrigatório - definir no Render
PREMIUM_PRICES = {
    'monthly': 6.99,
    'yearly': 80.99
}

# Forms customizados com validações adicionais
class SubscriptionForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="O email é obrigatório"),
        Email(message="Por favor, insira um email válido")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="A senha é obrigatória"),
        Length(min=8, message="A senha deve ter pelo menos 8 caracteres")
    ])
    subscription_type = HiddenField('Subscription Type', validators=[DataRequired()])

    def validate_subscription_type(self, field):
        if field.data not in PAGBANK_LINKS:
            raise ValidationError('Tipo de assinatura inválido')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="O email é obrigatório"),
        Email(message="Por favor, insira um email válido")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="A senha é obrigatória")
    ])

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="O nome de usuário é obrigatório")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="A senha é obrigatória")
    ])

# JSON Encoder customizado
class FlaskJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, '__html__'):
            return str(o.__html__())
        return super().default(o)

app.json_encoder = FlaskJSONEncoder

# Configuração de logging
logging.basicConfig(
    level=app.config['LOG_LEVEL'],
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Helpers de banco de dados
def get_db():
    """Obtém uma conexão com o banco de dados com tratamento de erro"""
    try:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
        db.execute('PRAGMA busy_timeout = 5000')  # Timeout para evitar locks
        return db
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def init_db():
    """Inicializa o banco de dados com as tabelas necessárias"""
    db = None
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        
        # Verifica se o diretório é gravável
        if not os.access(app.instance_path, os.W_OK):
            raise RuntimeError(f"Instance path is not writable: {app.instance_path}")
        
        db = get_db()
        
        # Criação das tabelas com schema atualizado
        db.execute('''
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                home_team TEXT NOT NULL CHECK(length(home_team) <= 100),
                away_team TEXT NOT NULL CHECK(length(away_team) <= 100),
                competition TEXT CHECK(length(competition) <= 100),
                location TEXT CHECK(length(location) <= 100),
                match_date TEXT NOT NULL CHECK(match_date LIKE '____-__-__'),
                match_time TEXT NOT NULL CHECK(match_time LIKE '__:__'),
                predicted_score TEXT CHECK(length(predicted_score) <= 10),
                home_win_percent INTEGER DEFAULT 0 CHECK(home_win_percent BETWEEN 0 AND 100),
                draw_percent INTEGER DEFAULT 0 CHECK(draw_percent BETWEEN 0 AND 100),
                away_win_percent INTEGER DEFAULT 0 CHECK(away_win_percent BETWEEN 0 AND 100),
                over_05_percent INTEGER DEFAULT 0 CHECK(over_05_percent BETWEEN 0 AND 100),
                over_15_percent INTEGER DEFAULT 0 CHECK(over_15_percent BETWEEN 0 AND 100),
                over_25_percent INTEGER DEFAULT 0 CHECK(over_25_percent BETWEEN 0 AND 100),
                over_35_percent INTEGER DEFAULT 0 CHECK(over_35_percent BETWEEN 0 AND 100),
                btts_percent INTEGER DEFAULT 0 CHECK(btts_percent BETWEEN 0 AND 100),
                btts_no_percent INTEGER DEFAULT 0 CHECK(btts_no_percent BETWEEN 0 AND 100),
                yellow_cards_predicted REAL DEFAULT 0 CHECK(yellow_cards_predicted >= 0),
                red_cards_predicted REAL DEFAULT 0 CHECK(red_cards_predicted >= 0),
                corners_predicted REAL DEFAULT 0 CHECK(corners_predicted >= 0),
                corners_home_predicted REAL DEFAULT 0 CHECK(corners_home_predicted >= 0),
                corners_away_predicted REAL DEFAULT 0 CHECK(corners_away_predicted >= 0),
                possession_home INTEGER DEFAULT 50 CHECK(possession_home BETWEEN 0 AND 100),
                possession_away INTEGER DEFAULT 50 CHECK(possession_away BETWEEN 0 AND 100),
                shots_on_target_home INTEGER DEFAULT 0 CHECK(shots_on_target_home >= 0),
                shots_on_target_away INTEGER DEFAULT 0 CHECK(shots_on_target_away >= 0),
                shots_off_target_home INTEGER DEFAULT 0 CHECK(shots_off_target_home >= 0),
                shots_off_target_away INTEGER DEFAULT 0 CHECK(shots_off_target_away >= 0),
                fouls_home INTEGER DEFAULT 0 CHECK(fouls_home >= 0),
                fouls_away INTEGER DEFAULT 0 CHECK(fouls_away >= 0),
                offsides_home INTEGER DEFAULT 0 CHECK(offsides_home >= 0),
                offsides_away INTEGER DEFAULT 0 CHECK(offsides_away >= 0),
                safe_prediction TEXT CHECK(length(safe_prediction) <= 200),
                risk_prediction TEXT CHECK(length(risk_prediction) <= 200),
                details TEXT,
                display_order INTEGER DEFAULT 0,
                color_scheme TEXT DEFAULT 'blue' CHECK(color_scheme IN ('blue', 'green', 'red', 'yellow')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        db.execute('''
            CREATE TRIGGER IF NOT EXISTS update_matches_timestamp
            AFTER UPDATE ON matches
            FOR EACH ROW
            BEGIN
                UPDATE matches SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END;
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL CHECK(length(email) <= 255),
                password TEXT NOT NULL,
                is_premium BOOLEAN DEFAULT 0,
                premium_expiry TEXT CHECK(premium_expiry LIKE '____-__-__' OR premium_expiry IS NULL),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                account_locked BOOLEAN DEFAULT 0
            )
        ''')
        
        db.execute('''
            CREATE TRIGGER IF NOT EXISTS update_users_timestamp
            AFTER UPDATE ON users
            FOR EACH ROW
            BEGIN
                UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END;
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subscription_type TEXT NOT NULL CHECK(subscription_type IN ('monthly', 'yearly')),
                payment_amount REAL NOT NULL CHECK(payment_amount > 0),
                payment_date TEXT NOT NULL CHECK(payment_date LIKE '____-__-__ __:__:__'),
                expiry_date TEXT NOT NULL CHECK(expiry_date LIKE '____-__-__'),
                is_active BOOLEAN DEFAULT 1,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'failed', 'refunded')),
                transaction_id TEXT UNIQUE CHECK(length(transaction_id) <= 100),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        db.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise RuntimeError(f"Failed to initialize database: {str(e)}")
    finally:
        if db:
            db.close()

# Inicializa o banco de dados
with app.app_context():
    try:
        init_db()
    except Exception as e:
        logger.critical(f"Failed to initialize database: {str(e)}")
        # Em produção, você pode querer encerrar o aplicativo aqui
        # raise SystemExit(1)

# Decorators de segurança
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Acesso restrito a usuários premium', 'danger')
            return redirect(url_for('premium_subscription'))
        
        # Verifica se a conta ainda existe
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            if not user:
                session.clear()
                flash('Sua conta não foi encontrada', 'danger')
                return redirect(url_for('user_login'))
            
            # Verifica se a conta está bloqueada
            if user['account_locked']:
                session.clear()
                flash('Sua conta está temporariamente bloqueada', 'danger')
                return redirect(url_for('user_login'))
        finally:
            db.close()
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Acesso restrito a administradores', 'danger')
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Helpers de aplicativo
def sanitize_input(text, max_length=None):
    """Sanitiza entrada do usuário para prevenir XSS"""
    if text is None:
        return None
    cleaned = clean(str(text).strip()
    if max_length and len(cleaned) > max_length:
        return cleaned[:max_length]
    return cleaned

def format_date(date_str):
    """Formata a data para exibição"""
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
    except (ValueError, TypeError):
        return date_str

def check_premium_status(user_id):
    """Verifica o status premium do usuário"""
    db = get_db()
    try:
        user = db.execute('''
            SELECT is_premium, premium_expiry 
            FROM users 
            WHERE id = ? AND account_locked = 0
        ''', (user_id,)).fetchone()
        
        if user and user['is_premium'] and user['premium_expiry']:
            expiry_date = datetime.strptime(user['premium_expiry'], '%Y-%m-%d')
            return expiry_date >= datetime.now()
        return False
    except Exception as e:
        logger.error(f"Error checking premium status: {str(e)}")
        return False
    finally:
        db.close()

def get_numeric_value(key, default=0, min_val=None, max_val=None):
    """Obtém um valor numérico do formulário com validação"""
    value = request.form.get(key)
    try:
        num = int(value)
        if min_val is not None and num < min_val:
            return min_val
        if max_val is not None and num > max_val:
            return max_val
        return num
    except (TypeError, ValueError):
        return default

def get_float_value(key, default=0.0, min_val=None, max_val=None):
    """Obtém um valor float do formulário com validação"""
    value = request.form.get(key)
    try:
        num = float(value)
        if min_val is not None and num < min_val:
            return min_val
        if max_val is not None and num > max_val:
            return max_val
        return num
    except (TypeError, ValueError):
        return default

# Rotas do aplicativo
@app.route('/')
@login_required
def index():
    """Página principal com as previsões de jogos"""
    try:
        db = get_db()
        today = datetime.now().strftime('%Y-%m-%d')
        next_week = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
        
        matches = db.execute('''
            SELECT * FROM matches 
            WHERE match_date BETWEEN ? AND ?
            ORDER BY display_order, match_date, match_time
        ''', (today, next_week)).fetchall()
        
        today_matches = []
        other_matches = []
        
        for m in matches:
            match = dict(m)
            match['is_today'] = match['match_date'] == today
            match['formatted_date'] = format_date(match['match_date'])
            
            if match['is_today']:
                today_matches.append(match)
            else:
                other_matches.append(match)
        
        last_updated = datetime.now().strftime('%d/%m/%Y às %H:%M')
        return render_template('index.html',
                            today_matches=today_matches,
                            other_matches=other_matches,
                            last_updated=last_updated,
                            is_premium=session.get('is_premium', False))
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return render_template('error.html', message="Error loading data"), 500
    finally:
        db.close()

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    """Página de assinatura premium"""
    form = SubscriptionForm()
    
    if form.validate_on_submit():
        email = sanitize_input(form.email.data, 255)
        password = form.password.data
        subscription_type = form.subscription_type.data
        
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                # Usuário existente
                if check_password_hash(user['password'], password):
                    if user['account_locked']:
                        flash('Sua conta está temporariamente bloqueada', 'danger')
                        return redirect(url_for('user_login'))
                    
                    # Resetar tentativas de login se bem-sucedido
                    db.execute('UPDATE users SET login_attempts = 0 WHERE id = ?', (user['id'],))
                    
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['is_premium'] = check_premium_status(user['id'])
                    
                    # Registrar último login
                    db.execute('''
                        UPDATE users SET 
                            last_login = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (user['id'],))
                    db.commit()
                    
                    return redirect(PAGBANK_LINKS[subscription_type])
                else:
                    # Incrementar tentativas de login
                    attempts = user['login_attempts'] + 1
                    db.execute('''
                        UPDATE users SET 
                            login_attempts = ?,
                            account_locked = CASE WHEN ? >= 5 THEN 1 ELSE 0 END
                        WHERE id = ?
                    ''', (attempts, attempts, user['id']))
                    db.commit()
                    
                    if attempts >= 5:
                        flash('Sua conta foi temporariamente bloqueada devido a muitas tentativas falhas', 'danger')
                    else:
                        flash('Senha incorreta', 'danger')
                    return redirect(url_for('user_login'))
            
            # Novo usuário
            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            user_id = db.lastrowid
            
            # Criar registro de assinatura
            payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            expiry_date = (datetime.now() + timedelta(
                days=30 if subscription_type == 'monthly' else 365
            )).strftime('%Y-%m-%d')
            
            db.execute('''
                INSERT INTO subscriptions (
                    user_id, subscription_type, payment_amount, 
                    payment_date, expiry_date, status
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id, 
                subscription_type, 
                PREMIUM_PRICES[subscription_type],
                payment_date, 
                expiry_date, 
                'pending'
            ))
            
            db.commit()
            
            session['logged_in'] = True
            session['user_id'] = user_id
            session['is_premium'] = False
            
            return redirect(PAGBANK_LINKS[subscription_type])
            
        except sqlite3.IntegrityError:
            db.rollback()
            flash('Erro ao criar conta. Este email já está em uso.', 'danger')
        except Exception as e:
            db.rollback()
            logger.error(f"Erro no processamento da assinatura: {str(e)}")
            flash('Erro ao processar sua assinatura. Por favor, tente novamente.', 'danger')
        finally:
            db.close()
    
    return render_template('premium.html', form=form, pagbank_links=PAGBANK_LINKS)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    """Página de login para usuários"""
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = sanitize_input(form.email.data, 255)
        password = form.password.data
        
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if not user:
                flash('Email não encontrado', 'danger')
                return redirect(url_for('user_login'))
            
            if user['account_locked']:
                flash('Sua conta está temporariamente bloqueada', 'danger')
                return redirect(url_for('user_login'))
            
            if check_password_hash(user['password'], password):
                # Login bem-sucedido - resetar tentativas
                db.execute('''
                    UPDATE users SET 
                        login_attempts = 0,
                        last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user['id'],))
                db.commit()
                
                session.clear()
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['is_premium'] = check_premium_status(user['id'])
                
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('index'))
            else:
                # Incrementar tentativas de login
                attempts = user['login_attempts'] + 1
                db.execute('''
                    UPDATE users SET 
                        login_attempts = ?,
                        account_locked = CASE WHEN ? >= 5 THEN 1 ELSE 0 END
                    WHERE id = ?
                ''', (attempts, attempts, user['id']))
                db.commit()
                
                if attempts >= 5:
                    flash('Sua conta foi temporariamente bloqueada devido a muitas tentativas falhas', 'danger')
                else:
                    flash('Email ou senha incorretos', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Erro durante o login', 'danger')
        finally:
            db.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """Logout do usuário"""
    session.clear()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Página de login para administradores"""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data, 50)
        password = form.password.data
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear()
            session['admin_logged_in'] = True
            flash('Login de administrador realizado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Credenciais de administrador incorretas', 'danger')
    
    return render_template('admin_login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    """Logout do administrador"""
    session.pop('admin_logged_in', None)
    flash('Administrador desconectado', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    """Redireciona para o login de admin"""
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Painel de controle do administrador"""
    try:
        db = get_db()
        matches = db.execute('''
            SELECT id, home_team, away_team, match_date, match_time 
            FROM matches 
            ORDER BY match_date, match_time
        ''').fetchall()
        
        users = db.execute('''
            SELECT id, email, is_premium, premium_expiry, created_at 
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 10
        ''').fetchall()
        
        subscriptions = db.execute('''
            SELECT s.id, u.email, s.subscription_type, s.payment_amount, 
                   s.payment_date, s.expiry_date, s.status
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.payment_date DESC
            LIMIT 10
        ''').fetchall()
        
        return render_template('admin/dashboard.html', 
                             matches=matches,
                             users=users,
                             subscriptions=subscriptions)
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        return render_template('error.html', message="Erro ao carregar o painel"), 500
    finally:
        db.close()

@app.route('/admin/match/add', methods=['GET', 'POST'])
@admin_required
def add_match():
    """Adiciona um novo jogo"""
    if request.method == 'POST':
        try:
            # Sanitizar e validar dados
            home_team = sanitize_input(request.form.get('home_team'), 100)
            away_team = sanitize_input(request.form.get('away_team'), 100)
            match_date = request.form.get('match_date')
            match_time = request.form.get('match_time')
            
            if not all([home_team, away_team, match_date, match_time]):
                flash('Preencha todos os campos obrigatórios', 'danger')
                return redirect(url_for('add_match'))
            
            # Validar formato da data e hora
            try:
                datetime.strptime(match_date, '%Y-%m-%d')
                datetime.strptime(match_time, '%H:%M')
            except ValueError:
                flash('Formato de data ou hora inválido', 'danger')
                return redirect(url_for('add_match'))
            
            db = get_db()
            db.execute('''
                INSERT INTO matches (
                    home_team, away_team, competition, location, 
                    match_date, match_time, predicted_score,
                    home_win_percent, away_win_percent, draw_percent,
                    over_05_percent, over_15_percent, over_25_percent, over_35_percent,
                    btts_percent, btts_no_percent, yellow_cards_predicted,
                    red_cards_predicted, corners_predicted, corners_home_predicted,
                    corners_away_predicted, possession_home, possession_away,
                    shots_on_target_home, shots_on_target_away, shots_off_target_home,
                    shots_off_target_away, fouls_home, fouls_away, offsides_home,
                    offsides_away, safe_prediction, risk_prediction, details,
                    display_order, color_scheme
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                home_team,
                away_team,
                sanitize_input(request.form.get('competition'), 100),
                sanitize_input(request.form.get('location'), 100),
                match_date,
                match_time,
                sanitize_input(request.form.get('predicted_score'), 10),
                get_numeric_value('home_win_percent', min_val=0, max_val=100),
                get_numeric_value('away_win_percent', min_val=0, max_val=100),
                get_numeric_value('draw_percent', min_val=0, max_val=100),
                get_numeric_value('over_05_percent', min_val=0, max_val=100),
                get_numeric_value('over_15_percent', min_val=0, max_val=100),
                get_numeric_value('over_25_percent', min_val=0, max_val=100),
                get_numeric_value('over_35_percent', min_val=0, max_val=100),
                get_numeric_value('btts_percent', min_val=0, max_val=100),
                get_numeric_value('btts_no_percent', min_val=0, max_val=100),
                get_float_value('yellow_cards_predicted', min_val=0),
                get_float_value('red_cards_predicted', min_val=0),
                get_float_value('corners_predicted', min_val=0),
                get_float_value('corners_home_predicted', min_val=0),
                get_float_value('corners_away_predicted', min_val=0),
                get_numeric_value('possession_home', 50, 0, 100),
                get_numeric_value('possession_away', 50, 0, 100),
                get_numeric_value('shots_on_target_home', min_val=0),
                get_numeric_value('shots_on_target_away', min_val=0),
                get_numeric_value('shots_off_target_home', min_val=0),
                get_numeric_value('shots_off_target_away', min_val=0),
                get_numeric_value('fouls_home', min_val=0),
                get_numeric_value('fouls_away', min_val=0),
                get_numeric_value('offsides_home', min_val=0),
                get_numeric_value('offsides_away', min_val=0),
                sanitize_input(request.form.get('safe_prediction'), 200),
                sanitize_input(request.form.get('risk_prediction'), 200),
                sanitize_input(request.form.get('details')),
                get_numeric_value('display_order'),
                sanitize_input(request.form.get('color_scheme', 'blue'))
            ))
            db.commit()
            flash('Jogo adicionado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        except sqlite3.Error as e:
            db.rollback()
            logger.error(f"Error adding match: {str(e)}")
            flash('Erro ao adicionar jogo. Verifique os dados.', 'danger')
            return redirect(url_for('add_match'))
        except Exception as e:
            if 'db' in locals() and db:
                db.rollback()
            logger.error(f"Unexpected error adding match: {str(e)}")
            flash('Erro inesperado ao adicionar jogo', 'danger')
            return redirect(url_for('add_match'))
        finally:
            if 'db' in locals() and db:
                db.close()
    
    return render_template('admin/add_match.html')

@app.route('/admin/match/edit/<int:match_id>', methods=['GET', 'POST'])
@admin_required
def edit_match(match_id):
    """Edita um jogo existente"""
    db = get_db()
    try:
        if request.method == 'POST':
            # Sanitizar e validar dados
            home_team = sanitize_input(request.form.get('home_team'), 100)
            away_team = sanitize_input(request.form.get('away_team'), 100)
            match_date = request.form.get('match_date')
            match_time = request.form.get('match_time')
            
            if not all([home_team, away_team, match_date, match_time]):
                flash('Preencha todos os campos obrigatórios', 'danger')
                return redirect(url_for('edit_match', match_id=match_id))
            
            # Validar formato da data e hora
            try:
                datetime.strptime(match_date, '%Y-%m-%d')
                datetime.strptime(match_time, '%H:%M')
            except ValueError:
                flash('Formato de data ou hora inválido', 'danger')
                return redirect(url_for('edit_match', match_id=match_id))
            
            db.execute('''
                UPDATE matches SET
                    home_team = ?,
                    away_team = ?,
                    competition = ?,
                    location = ?,
                    match_date = ?,
                    match_time = ?,
                    predicted_score = ?,
                    home_win_percent = ?,
                    away_win_percent = ?,
                    draw_percent = ?,
                    over_05_percent = ?,
                    over_15_percent = ?,
                    over_25_percent = ?,
                    over_35_percent = ?,
                    btts_percent = ?,
                    btts_no_percent = ?,
                    yellow_cards_predicted = ?,
                    red_cards_predicted = ?,
                    corners_predicted = ?,
                    corners_home_predicted = ?,
                    corners_away_predicted = ?,
                    possession_home = ?,
                    possession_away = ?,
                    shots_on_target_home = ?,
                    shots_on_target_away = ?,
                    shots_off_target_home = ?,
                    shots_off_target_away = ?,
                    fouls_home = ?,
                    fouls_away = ?,
                    offsides_home = ?,
                    offsides_away = ?,
                    safe_prediction = ?,
                    risk_prediction = ?,
                    details = ?,
                    display_order = ?,
                    color_scheme = ?
                WHERE id = ?
            ''', (
                home_team,
                away_team,
                sanitize_input(request.form.get('competition'), 100),
                sanitize_input(request.form.get('location'), 100),
                match_date,
                match_time,
                sanitize_input(request.form.get('predicted_score'), 10),
                get_numeric_value('home_win_percent', min_val=0, max_val=100),
                get_numeric_value('away_win_percent', min_val=0, max_val=100),
                get_numeric_value('draw_percent', min_val=0, max_val=100),
                get_numeric_value('over_05_percent', min_val=0, max_val=100),
                get_numeric_value('over_15_percent', min_val=0, max_val=100),
                get_numeric_value('over_25_percent', min_val=0, max_val=100),
                get_numeric_value('over_35_percent', min_val=0, max_val=100),
                get_numeric_value('btts_percent', min_val=0, max_val=100),
                get_numeric_value('btts_no_percent', min_val=0, max_val=100),
                get_float_value('yellow_cards_predicted', min_val=0),
                get_float_value('red_cards_predicted', min_val=0),
                get_float_value('corners_predicted', min_val=0),
                get_float_value('corners_home_predicted', min_val=0),
                get_float_value('corners_away_predicted', min_val=0),
                get_numeric_value('possession_home', 50, 0, 100),
                get_numeric_value('possession_away', 50, 0, 100),
                get_numeric_value('shots_on_target_home', min_val=0),
                get_numeric_value('shots_on_target_away', min_val=0),
                get_numeric_value('shots_off_target_home', min_val=0),
                get_numeric_value('shots_off_target_away', min_val=0),
                get_numeric_value('fouls_home', min_val=0),
                get_numeric_value('fouls_away', min_val=0),
                get_numeric_value('offsides_home', min_val=0),
                get_numeric_value('offsides_away', min_val=0),
                sanitize_input(request.form.get('safe_prediction'), 200),
                sanitize_input(request.form.get('risk_prediction'), 200),
                sanitize_input(request.form.get('details')),
                get_numeric_value('display_order'),
                sanitize_input(request.form.get('color_scheme', 'blue')),
                match_id
            ))
            db.commit()
            flash('Jogo atualizado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        match = db.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
        if not match:
            flash('Jogo não encontrado', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        return render_template('admin/edit_match.html', match=dict(match))
    except Exception as e:
        logger.error(f"Error editing match: {str(e)}")
        flash('Erro ao editar jogo', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/match/delete/<int:match_id>', methods=['POST'])
@admin_required
def delete_match(match_id):
    """Exclui um jogo"""
    db = get_db()
    try:
        db.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        db.commit()
        flash('Jogo excluído com sucesso', 'success')
    except Exception as e:
        logger.error(f"Error deleting match: {str(e)}")
        flash('Erro ao excluir jogo', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/payment/verify', methods=['GET', 'POST'])
@csrf.exempt  # Temporário - adicionar CSRF token no form
def payment_verify():
    """Verificação de pagamento (simplificada para o Render Free)"""
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'), 255)
        transaction_id = sanitize_input(request.form.get('transaction_id'), 100)
        
        if not email:
            flash('Email é obrigatório', 'danger')
            return redirect(url_for('payment_verify'))
        
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if not user:
                flash('Email não encontrado', 'danger')
                return redirect(url_for('payment_verify'))
            
            # Verifica pagamentos recentes (simulado para o Render Free)
            recent_payment = db.execute('''
                SELECT * FROM subscriptions 
                WHERE user_id = ? 
                AND payment_date >= datetime('now', '-30 minutes')
                ORDER BY payment_date DESC
                LIMIT 1
            ''', (user['id'],)).fetchone()
            
            if recent_payment:
                # Atualiza status do usuário para premium
                db.execute('''
                    UPDATE users SET 
                        is_premium = 1,
                        premium_expiry = ?
                    WHERE id = ?
                ''', (recent_payment['expiry_date'], user['id']))
                
                # Atualiza status da assinatura
                db.execute('''
                    UPDATE subscriptions SET 
                        is_active = 1,
                        status = 'completed',
                        transaction_id = ?
                    WHERE id = ?
                ''', (transaction_id or 'simulated_' + str(datetime.now().timestamp()), recent_payment['id']))
                
                db.commit()
                session['is_premium'] = True
                flash('Pagamento confirmado! Acesso premium ativado.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Nenhum pagamento recente encontrado para este email', 'warning')
                return redirect(url_for('payment_verify'))
        except Exception as e:
            logger.error(f"Payment verification error: {str(e)}")
            flash('Erro na verificação de pagamento', 'danger')
            return redirect(url_for('payment_verify'))
        finally:
            db.close()
    
    return render_template('payment_verify.html')

# Handlers de erro
@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 error: {request.url}")
    return render_template('error.html', message="Página não encontrada"), 404

@app.errorhandler(403)
def forbidden(e):
    logger.warning(f"403 error: {request.url}")
    return render_template('error.html', message="Acesso não autorizado"), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('error.html', message="Erro interno do servidor"), 500

@app.errorhandler(sqlite3.Error)
def handle_db_errors(e):
    logger.error(f"Database error: {str(e)}")
    return render_template('error.html', message="Erro de banco de dados"), 500

# Inicialização do aplicativo
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)