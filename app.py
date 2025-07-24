import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Email, Length
from wtforms.validators import ValidationError
import json
from bleach import clean

# Configuração inicial do app
app = Flask(__name__)

# Configurações otimizadas para o Render
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(32).hex()),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', os.urandom(32).hex()),
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    TEMPLATES_AUTO_RELOAD=True,
    DATABASE=os.path.join(app.instance_path, 'matches.db'),
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'matches.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

# Proteção CSRF
csrf = CSRFProtect(app)

# Links de pagamento
PAGBANK_LINKS = {
    'monthly': 'https://pag.ae/7_TnPtRxH',
    'yearly': 'https://pag.ae/7_TnQbYun'
}

# Forms customizados
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
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constantes
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123premium')
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

# Helpers de banco de dados
def get_db():
    """Obtém uma conexão com o banco de dados"""
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    return db

def init_db():
    """Inicializa o banco de dados"""
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        db = get_db()
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                home_team TEXT NOT NULL,
                away_team TEXT NOT NULL,
                competition TEXT,
                location TEXT,
                match_date TEXT NOT NULL,
                match_time TEXT NOT NULL,
                predicted_score TEXT,
                home_win_percent INTEGER DEFAULT 0,
                draw_percent INTEGER DEFAULT 0,
                away_win_percent INTEGER DEFAULT 0,
                over_05_percent INTEGER DEFAULT 0,
                over_15_percent INTEGER DEFAULT 0,
                over_25_percent INTEGER DEFAULT 0,
                over_35_percent INTEGER DEFAULT 0,
                btts_percent INTEGER DEFAULT 0,
                btts_no_percent INTEGER DEFAULT 0,
                yellow_cards_predicted REAL DEFAULT 0,
                red_cards_predicted REAL DEFAULT 0,
                corners_predicted REAL DEFAULT 0,
                corners_home_predicted REAL DEFAULT 0,
                corners_away_predicted REAL DEFAULT 0,
                possession_home INTEGER DEFAULT 50,
                possession_away INTEGER DEFAULT 50,
                shots_on_target_home INTEGER DEFAULT 0,
                shots_on_target_away INTEGER DEFAULT 0,
                shots_off_target_home INTEGER DEFAULT 0,
                shots_off_target_away INTEGER DEFAULT 0,
                fouls_home INTEGER DEFAULT 0,
                fouls_away INTEGER DEFAULT 0,
                offsides_home INTEGER DEFAULT 0,
                offsides_away INTEGER DEFAULT 0,
                safe_prediction TEXT,
                risk_prediction TEXT,
                details TEXT,
                display_order INTEGER DEFAULT 0,
                color_scheme TEXT DEFAULT 'blue',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
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
                is_active BOOLEAN DEFAULT 1,
                status TEXT DEFAULT 'pending',
                transaction_id TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        db.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise
    finally:
        db.close()

# Inicializa o banco de dados
with app.app_context():
    init_db()

# Decorators de segurança
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Acesso restrito a usuários premium', 'danger')
            return redirect(url_for('premium_subscription'))
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
    """Sanitiza entrada do usuário"""
    if text is None:
        return None
    cleaned = clean(str(text).strip())
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
        user = db.execute('SELECT is_premium, premium_expiry FROM users WHERE id = ?', (user_id,)).fetchone()
        if user and user['is_premium'] and user['premium_expiry']:
            expiry_date = datetime.strptime(user['premium_expiry'], '%Y-%m-%d')
            return expiry_date >= datetime.now()
        return False
    except Exception as e:
        logger.error(f"Error checking premium status: {str(e)}")
        return False
    finally:
        db.close()

def get_numeric_value(key, default=0):
    """Obtém valor numérico do formulário"""
    value = request.form.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def get_float_value(key, default=0.0):
    """Obtém valor float do formulário"""
    value = request.form.get(key)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

# Rotas principais
@app.route('/')
@login_required
def index():
    """Página principal"""
    try:
        db = get_db()
        today = datetime.now().strftime('%Y-%m-%d')
        next_week = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
        
        matches = db.execute('''
            SELECT * FROM matches 
            WHERE match_date BETWEEN ? AND ?
            ORDER BY display_order, match_date, match_time
        ''', (today, next_week)).fetchall()
        
        today_matches = [dict(m) for m in matches if m['match_date'] == today]
        other_matches = [dict(m) for m in matches if m['match_date'] != today]
        
        for m in today_matches + other_matches:
            m['formatted_date'] = format_date(m['match_date'])
        
        return render_template('index.html',
                            today_matches=today_matches,
                            other_matches=other_matches,
                            is_premium=session.get('is_premium', False))
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return render_template('error.html', message="Erro ao carregar dados"), 500
    finally:
        db.close()

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    """Página de assinatura premium"""
    form = SubscriptionForm()
    
    if form.validate_on_submit():
        email = sanitize_input(form.email.data)
        password = form.password.data
        subscription_type = form.subscription_type.data
        
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                if check_password_hash(user['password'], password):
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['is_premium'] = check_premium_status(user['id'])
                    return redirect(PAGBANK_LINKS[subscription_type])
                else:
                    flash('Senha incorreta', 'danger')
                    return redirect(url_for('user_login'))
            
            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            user_id = db.lastrowid
            
            payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if subscription_type == 'monthly':
                expiry_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
                payment_amount = 6.99
            else:
                expiry_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
                payment_amount = 80.99
            
            db.execute('''
                INSERT INTO subscriptions (
                    user_id, subscription_type, payment_amount, 
                    payment_date, expiry_date, status
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, subscription_type, payment_amount, payment_date, expiry_date, 'pending'))
            
            db.commit()
            
            session['logged_in'] = True
            session['user_id'] = user_id
            session['is_premium'] = False
            
            return redirect(PAGBANK_LINKS[subscription_type])
            
        except Exception as e:
            db.rollback()
            logger.error(f"Subscription error: {str(e)}")
            flash('Erro no processamento', 'danger')
        finally:
            db.close()
    
    return render_template('premium.html', form=form, pagbank_links=PAGBANK_LINKS)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    """Página de login"""
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = sanitize_input(form.email.data)
        password = form.password.data
        
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['is_premium'] = check_premium_status(user['id'])
                return redirect(url_for('index'))
            else:
                flash('Email ou senha incorretos', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Erro no login', 'danger')
        finally:
            db.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """Logout do usuário"""
    session.clear()
    return redirect(url_for('index'))

# Rotas administrativas
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Login administrativo"""
    form = AdminLoginForm()
    if form.validate_on_submit():
        if (form.username.data == ADMIN_USERNAME and 
            check_password_hash(ADMIN_PASSWORD_HASH, form.password.data)):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Credenciais inválidas', 'danger')
    return render_template('admin/login.html', form=form)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Painel administrativo"""
    try:
        db = get_db()
        matches = db.execute('SELECT * FROM matches ORDER BY match_date, match_time').fetchall()
        return render_template('admin/dashboard.html', matches=matches)
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        return render_template('error.html', message="Erro ao carregar dados"), 500
    finally:
        db.close()

@app.route('/admin/match/add', methods=['GET', 'POST'])
@admin_required
def add_match():
    """Adicionar partida"""
    if request.method == 'POST':
        db = get_db()
        try:
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
                request.form.get('home_team'),
                request.form.get('away_team'),
                request.form.get('competition'),
                request.form.get('location'),
                request.form.get('match_date'),
                request.form.get('match_time'),
                request.form.get('predicted_score'),
                get_numeric_value('home_win_percent'),
                get_numeric_value('away_win_percent'),
                get_numeric_value('draw_percent'),
                get_numeric_value('over_05_percent'),
                get_numeric_value('over_15_percent'),
                get_numeric_value('over_25_percent'),
                get_numeric_value('over_35_percent'),
                get_numeric_value('btts_percent'),
                get_numeric_value('btts_no_percent'),
                get_float_value('yellow_cards_predicted'),
                get_float_value('red_cards_predicted'),
                get_float_value('corners_predicted'),
                get_float_value('corners_home_predicted'),
                get_float_value('corners_away_predicted'),
                get_numeric_value('possession_home', 50),
                get_numeric_value('possession_away', 50),
                get_numeric_value('shots_on_target_home'),
                get_numeric_value('shots_on_target_away'),
                get_numeric_value('shots_off_target_home'),
                get_numeric_value('shots_off_target_away'),
                get_numeric_value('fouls_home'),
                get_numeric_value('fouls_away'),
                get_numeric_value('offsides_home'),
                get_numeric_value('offsides_away'),
                request.form.get('safe_prediction'),
                request.form.get('risk_prediction'),
                request.form.get('details'),
                get_numeric_value('display_order'),
                request.form.get('color_scheme', 'blue')
            ))
            db.commit()
            flash('Partida adicionada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.rollback()
            logger.error(f"Error adding match: {str(e)}")
            flash('Erro ao adicionar partida', 'danger')
        finally:
            db.close()
    
    return render_template('admin/add_match.html')

@app.route('/admin/match/edit/<int:match_id>', methods=['GET', 'POST'])
@admin_required
def edit_match(match_id):
    """Editar partida"""
    db = get_db()
    try:
        if request.method == 'POST':
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
                request.form.get('home_team'),
                request.form.get('away_team'),
                request.form.get('competition'),
                request.form.get('location'),
                request.form.get('match_date'),
                request.form.get('match_time'),
                request.form.get('predicted_score'),
                get_numeric_value('home_win_percent'),
                get_numeric_value('away_win_percent'),
                get_numeric_value('draw_percent'),
                get_numeric_value('over_05_percent'),
                get_numeric_value('over_15_percent'),
                get_numeric_value('over_25_percent'),
                get_numeric_value('over_35_percent'),
                get_numeric_value('btts_percent'),
                get_numeric_value('btts_no_percent'),
                get_float_value('yellow_cards_predicted'),
                get_float_value('red_cards_predicted'),
                get_float_value('corners_predicted'),
                get_float_value('corners_home_predicted'),
                get_float_value('corners_away_predicted'),
                get_numeric_value('possession_home', 50),
                get_numeric_value('possession_away', 50),
                get_numeric_value('shots_on_target_home'),
                get_numeric_value('shots_on_target_away'),
                get_numeric_value('shots_off_target_home'),
                get_numeric_value('shots_off_target_away'),
                get_numeric_value('fouls_home'),
                get_numeric_value('fouls_away'),
                get_numeric_value('offsides_home'),
                get_numeric_value('offsides_away'),
                request.form.get('safe_prediction'),
                request.form.get('risk_prediction'),
                request.form.get('details'),
                get_numeric_value('display_order'),
                request.form.get('color_scheme', 'blue'),
                match_id
            ))
            db.commit()
            flash('Partida atualizada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        match = db.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
        if not match:
            flash('Partida não encontrada', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        return render_template('admin/edit_match.html', match=match)
    except Exception as e:
        logger.error(f"Error editing match: {str(e)}")
        flash('Erro ao editar partida', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/match/delete/<int:match_id>', methods=['POST'])
@admin_required
def delete_match(match_id):
    """Excluir partida"""
    db = get_db()
    try:
        db.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        db.commit()
        flash('Partida excluída com sucesso', 'success')
    except Exception as e:
        logger.error(f"Error deleting match: {str(e)}")
        flash('Erro ao excluir partida', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/payment/verify', methods=['GET', 'POST'])
def payment_verify():
    """Verificação de pagamento"""
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if not user:
                flash('Email não encontrado', 'danger')
                return redirect(url_for('payment_verify'))
            
            recent_payment = db.execute('''
                SELECT * FROM subscriptions 
                WHERE user_id = ? 
                AND payment_date >= datetime('now', '-30 minutes')
                ORDER BY payment_date DESC
                LIMIT 1
            ''', (user['id'],)).fetchone()
            
            if recent_payment:
                db.execute('''
                    UPDATE users SET 
                        is_premium = 1,
                        premium_expiry = ?
                    WHERE id = ?
                ''', (recent_payment['expiry_date'], user['id']))
                
                db.execute('''
                    UPDATE subscriptions SET 
                        is_active = 1,
                        status = 'completed'
                    WHERE id = ?
                ''', (recent_payment['id'],))
                
                db.commit()
                session['is_premium'] = True
                flash('Pagamento confirmado! Acesso premium ativado.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Nenhum pagamento recente encontrado', 'warning')
                return redirect(url_for('payment_verify'))
        except Exception as e:
            logger.error(f"Payment verification error: {str(e)}")
            flash('Erro na verificação', 'danger')
            return redirect(url_for('payment_verify'))
        finally:
            db.close()
    
    return render_template('payment_verify.html')

# Handlers de erro
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Página não encontrada"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', message="Erro interno"), 500

# Ponto de entrada
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)