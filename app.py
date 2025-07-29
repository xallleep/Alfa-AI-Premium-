import os
import re
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, HiddenField, IntegerField, FloatField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, ValidationError, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import psycopg2
from psycopg2.pool import SimpleConnectionPool
import requests

# Configuração
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret-key')
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', 'fallback-csrf-key')
    DATABASE_URL = os.environ.get('DATABASE_URL')
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin_alfaai')
    ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'senhaadmin123'))
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    PAGBANK_LINKS = {
        'monthly': os.environ.get('PAGBANK_MONTHLY_LINK', 'https://pag.ae/7YwQq6rGd'),
        'yearly': os.environ.get('PAGBANK_YEARLY_LINK', 'https://pag.ae/7YwQq6rGd')
    }
    PAGBANK_API_KEY = os.environ.get('PAGBANK_API_KEY', '')
    PAGBANK_WEBHOOK_SECRET = os.environ.get('PAGBANK_WEBHOOK_SECRET', '')

app = Flask(__name__)
app.config.from_object(Config)

# Extensões
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s : %(message)s'
)
logger = logging.getLogger('alfaai')

# Database Pool
connection_pool = None

def init_connection_pool():
    global connection_pool
    if not connection_pool:
        db_url = app.config['DATABASE_URL']
        if db_url and db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        connection_pool = SimpleConnectionPool(
            minconn=1,
            maxconn=5,
            dsn=db_url,
            connect_timeout=5
        )

def get_db():
    init_connection_pool()
    conn = connection_pool.getconn()
    conn.autocommit = False
    return conn

def return_db(conn):
    if conn:
        try:
            connection_pool.putconn(conn)
        except Exception as e:
            logger.error(f"Error returning connection: {str(e)}")
            conn.close()

# Forms
class SubscriptionForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired("Email é obrigatório"),
        Email("Insira um email válido")
    ])
    password = PasswordField('Senha', validators=[
        DataRequired("Senha é obrigatória"),
        Length(8, 128, "Mínimo 8 caracteres")
    ])
    confirm_password = PasswordField('Confirmar Senha', validators=[
        DataRequired("Confirme sua senha")
    ])
    subscription_type = SelectField('Plano', choices=[
        ('monthly', 'Mensal - R$29,90'),
        ('yearly', 'Anual - R$299,00 (20% off)')
    ], validators=[DataRequired()])

    def validate_password(self, field):
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$', field.data):
            raise ValidationError('Senha precisa ter maiúsculas, minúsculas e números')

    def validate_confirm_password(self, field):
        if field.data != self.password.data:
            raise ValidationError('Senhas não coincidem')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired("Email é obrigatório"),
        Email("Insira um email válido")
    ])
    password = PasswordField('Senha', validators=[
        DataRequired("Senha é obrigatória")
    ])

class AdminLoginForm(FlaskForm):
    username = StringField('Usuário', validators=[
        DataRequired("Usuário é obrigatório")
    ])
    password = PasswordField('Senha', validators=[
        DataRequired("Senha é obrigatória")
    ])

class MatchForm(FlaskForm):
    home_team = StringField('Time Casa', validators=[DataRequired()])
    away_team = StringField('Time Visitante', validators=[DataRequired()])
    match_date = StringField('Data (YYYY-MM-DD)', validators=[DataRequired()])
    match_time = StringField('Hora (HH:MM)', validators=[DataRequired()])
    home_win = IntegerField('% Casa', validators=[NumberRange(0, 100)])
    draw = IntegerField('% Empate', validators=[NumberRange(0, 100)])
    away_win = IntegerField('% Visitante', validators=[NumberRange(0, 100)])
    over_15 = IntegerField('% Over 1.5', validators=[NumberRange(0, 100)])
    over_25 = IntegerField('% Over 2.5', validators=[NumberRange(0, 100)])
    cards = FloatField('Cartões', validators=[NumberRange(0)])
    corners = FloatField('Escanteios', validators=[NumberRange(0)])
    accuracy = IntegerField('% Acerto', validators=[NumberRange(0, 100)])
    details = TextAreaField('Análise')

# Helpers
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Faça login para acessar', 'warning')
            return redirect(url_for('user_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Acesso restrito', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_premium', False):
            flash('Assinatura premium requerida', 'warning')
            return redirect(url_for('premium_subscription'))
        return f(*args, **kwargs)
    return decorated_function

def is_premium_user(user_id):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            SELECT expiry_date FROM subscriptions 
            WHERE user_id = %s AND expiry_date >= CURRENT_DATE AND is_active = TRUE
            ORDER BY expiry_date DESC LIMIT 1
        ''', (user_id,))
        result = cur.fetchone()
        return result is not None
    except Exception as e:
        logger.error(f"Premium check error: {str(e)}")
        return False
    finally:
        if conn:
            return_db(conn)

def verify_pagbank_payment(payment_id):
    """Verifica o status de um pagamento no PagBank"""
    if not app.config['PAGBANK_API_KEY']:
        logger.warning("PagBank API key not configured - skipping payment verification")
        return True
        
    try:
        headers = {
            'Authorization': f'Bearer {app.config["PAGBANK_API_KEY"]}',
            'Content-Type': 'application/json'
        }
        response = requests.get(
            f'https://api.pagseguro.com/orders/{payment_id}',
            headers=headers
        )
        response.raise_for_status()
        data = response.json()
        
        return data.get('status') == 'PAID'
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}")
        return False

# Rotas Públicas
@app.route('/')
def index():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Pegar jogos de hoje
        cur.execute('''
            SELECT id, home_team, away_team, match_date, match_time,
                   home_win, draw, away_win, over_15, over_25,
                   cards, corners, accuracy, details
            FROM matches
            WHERE match_date = CURRENT_DATE
            ORDER BY match_time
        ''')
        today_matches = [dict(zip(
            ['id', 'home_team', 'away_team', 'date', 'time', 
             'home_win', 'draw', 'away_win', 'over_15', 'over_25',
             'cards', 'corners', 'accuracy', 'details'],
            row
        )) for row in cur.fetchall()]
        
        # Pegar próximos jogos
        cur.execute('''
            SELECT id, home_team, away_team, match_date, match_time,
                   home_win, draw, away_win, over_15, over_25,
                   cards, corners, accuracy, details
            FROM matches
            WHERE match_date > CURRENT_DATE
            ORDER BY match_date, match_time
            LIMIT 10
        ''')
        other_matches = [dict(zip(
            ['id', 'home_team', 'away_team', 'date', 'time', 
             'home_win', 'draw', 'away_win', 'over_15', 'over_25',
             'cards', 'corners', 'accuracy', 'details'],
            row
        )) for row in cur.fetchall()]
        
        # Formatar datas
        for m in today_matches + other_matches:
            if m['date']:
                m['date'] = m['date'].strftime('%d/%m/%Y')
            if m['time']:
                m['time'] = m['time'].strftime('%H:%M')
        
        return render_template('index.html',
                            today_matches=today_matches,
                            other_matches=other_matches,
                            last_updated=datetime.now().strftime('%d/%m/%Y %H:%M'),
                            is_premium=session.get('is_premium', False))
        
    except Exception as e:
        logger.error(f"Home error: {str(e)}")
        return render_template('index.html',
                            today_matches=[],
                            other_matches=[],
                            last_updated=datetime.now().strftime('%d/%m/%Y %H:%M'),
                            is_premium=session.get('is_premium', False))
    finally:
        if conn:
            return_db(conn)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('''
                SELECT id, password FROM users WHERE email = %s
            ''', (form.email.data,))
            user = cur.fetchone()
            
            if user and check_password_hash(user[1], form.password.data):
                session['logged_in'] = True
                session['user_id'] = user[0]
                session['is_premium'] = is_premium_user(user[0])
                flash('Login realizado!', 'success')
                
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Email ou senha incorretos', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Erro no login', 'danger')
        finally:
            if conn:
                return_db(conn)
    return render_template('login.html', form=form)

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    form = SubscriptionForm()
    if form.validate_on_submit():
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            
            # Verifica se usuário já existe
            cur.execute('SELECT id, password FROM users WHERE email = %s', (form.email.data,))
            user = cur.fetchone()
            
            if user:
                user_id = user[0]
                if not check_password_hash(user[1], form.password.data):
                    flash('Senha incorreta para este email', 'danger')
                    return redirect(url_for('premium_subscription'))
            else:
                # Cria novo usuário
                cur.execute('''
                    INSERT INTO users (email, password) 
                    VALUES (%s, %s) RETURNING id
                ''', (
                    form.email.data,
                    generate_password_hash(form.password.data)
                ))
                user_id = cur.fetchone()[0]
            
            # Cria assinatura pendente (será ativada após pagamento)
            expiry_date = datetime.now() + timedelta(
                days=365 if form.subscription_type.data == 'yearly' else 30
            )
            cur.execute('''
                INSERT INTO subscriptions (user_id, subscription_type, expiry_date, is_active)
                VALUES (%s, %s, %s, FALSE)
                RETURNING id
            ''', (user_id, form.subscription_type.data, expiry_date))
            subscription_id = cur.fetchone()[0]
            
            conn.commit()
            
            session['logged_in'] = True
            session['user_id'] = user_id
            session['subscription_id'] = subscription_id
            
            # Redireciona para PagBank
            payment_link = app.config['PAGBANK_LINKS'][form.subscription_type.data]
            return redirect(payment_link)
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Subscription error: {str(e)}")
            flash('Erro no processamento', 'danger')
        finally:
            if conn:
                return_db(conn)
    return render_template('premium.html', form=form)

@app.route('/payment/callback', methods=['POST'])
def payment_callback():
    # Verificar assinatura do webhook
    if request.headers.get('X-PagSeguro-Signature') != app.config['PAGBANK_WEBHOOK_SECRET']:
        abort(403)
    
    data = request.get_json()
    payment_id = data.get('id')
    status = data.get('status')
    
    if status == 'PAID':
        # Ativar assinatura
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            
            # Atualiza a assinatura como ativa
            cur.execute('''
                UPDATE subscriptions
                SET is_active = TRUE
                WHERE id = %s
            ''', (session.get('subscription_id'),))
            
            conn.commit()
            
            # Atualiza status premium na sessão
            if 'user_id' in session:
                session['is_premium'] = True
            
            logger.info(f"Payment {payment_id} confirmed - subscription activated")
            return '', 200
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Payment callback error: {str(e)}")
            return '', 500
        finally:
            if conn:
                return_db(conn)
    
    return '', 200

# Rotas Autenticadas
@app.route('/dashboard')
@login_required
def dashboard():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Verifica status da assinatura
        cur.execute('''
            SELECT expiry_date FROM subscriptions 
            WHERE user_id = %s AND is_active = TRUE
            ORDER BY expiry_date DESC LIMIT 1
        ''', (session['user_id'],))
        subscription = cur.fetchone()
        
        expiry_date = subscription[0] if subscription else None
        is_premium = expiry_date and expiry_date >= datetime.now().date()
        
        session['is_premium'] = is_premium
        
        return render_template('dashboard.html', 
                             is_premium=is_premium,
                             expiry_date=expiry_date)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render_template('dashboard.html', 
                             is_premium=False,
                             expiry_date=None)
    finally:
        if conn:
            return_db(conn)

@app.route('/premium/matches')
@login_required
@premium_required
def premium_matches():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            SELECT id, home_team, away_team, match_date, match_time,
                   home_win, draw, away_win, over_15, over_25,
                   cards, corners, accuracy, details
            FROM matches
            WHERE match_date >= CURRENT_DATE
            ORDER BY match_date, match_time
        ''')
        matches = [dict(zip(
            ['id', 'home_team', 'away_team', 'date', 'time', 
             'home_win', 'draw', 'away_win', 'over_15', 'over_25',
             'cards', 'corners', 'accuracy', 'details'],
            row
        )) for row in cur.fetchall()]
        
        # Formata datas
        for m in matches:
            if m['date']:
                m['date'] = m['date'].strftime('%d/%m/%Y')
            if m['time']:
                m['time'] = m['time'].strftime('%H:%M')
        
        return render_template('premium_matches.html', 
                            matches=matches,
                            last_updated=datetime.now().strftime('%d/%m/%Y %H:%M'))
    except Exception as e:
        logger.error(f"Matches error: {str(e)}")
        return render_template('premium_matches.html', matches=[])
    finally:
        if conn:
            return_db(conn)

# Rotas Admin
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        if (form.username.data == app.config['ADMIN_USERNAME'] and 
            check_password_hash(app.config['ADMIN_PASSWORD_HASH'], form.password.data)):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Credenciais inválidas', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM users')
        users = cur.fetchone()[0]
        cur.execute('SELECT COUNT(*) FROM matches')
        matches = cur.fetchone()[0]
        cur.execute('''
            SELECT COUNT(*) FROM subscriptions 
            WHERE is_active = TRUE AND expiry_date >= CURRENT_DATE
        ''')
        active_subscriptions = cur.fetchone()[0]
        return render_template('admin_dashboard.html', 
                             users=users, 
                             matches=matches,
                             active_subscriptions=active_subscriptions)
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        return render_template('admin_dashboard.html', 
                             users=0, 
                             matches=0,
                             active_subscriptions=0)
    finally:
        if conn:
            return_db(conn)

@app.route('/admin/matches/add', methods=['GET', 'POST'])
@admin_required
def add_match():
    form = MatchForm()
    if form.validate_on_submit():
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO matches (
                    home_team, away_team, match_date, match_time,
                    home_win, draw, away_win, over_15, over_25,
                    cards, corners, accuracy, details
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                form.home_team.data,
                form.away_team.data,
                form.match_date.data,
                form.match_time.data,
                form.home_win.data or 0,
                form.draw.data or 0,
                form.away_win.data or 0,
                form.over_15.data or 0,
                form.over_25.data or 0,
                form.cards.data or 0,
                form.corners.data or 0,
                form.accuracy.data or 0,
                form.details.data
            ))
            conn.commit()
            flash('Partida adicionada!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Add match error: {str(e)}")
            flash('Erro ao adicionar', 'danger')
        finally:
            if conn:
                return_db(conn)
    return render_template('add_match.html', form=form)

@app.route('/admin/matches/edit/<int:match_id>', methods=['GET', 'POST'])
@admin_required
def edit_match(match_id):
    form = MatchForm()
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        if request.method == 'GET':
            cur.execute('SELECT * FROM matches WHERE id = %s', (match_id,))
            match = cur.fetchone()
            if not match:
                flash('Partida não encontrada', 'danger')
                return redirect(url_for('admin_dashboard'))
            
            # Preenche o form
            form_fields = [
                'home_team', 'away_team', 'match_date', 'match_time',
                'home_win', 'draw', 'away_win', 'over_15', 'over_25',
                'cards', 'corners', 'accuracy', 'details'
            ]
            for i, field in enumerate(form_fields, 1):
                getattr(form, field).data = match[i]
            
            return render_template('edit_match.html', form=form, match_id=match_id)
        
        # Atualiza a partida
        cur.execute('''
            UPDATE matches SET
                home_team = %s, away_team = %s,
                match_date = %s, match_time = %s,
                home_win = %s, draw = %s, away_win = %s,
                over_15 = %s, over_25 = %s,
                cards = %s, corners = %s,
                accuracy = %s, details = %s
            WHERE id = %s
        ''', (
            form.home_team.data, form.away_team.data,
            form.match_date.data, form.match_time.data,
            form.home_win.data or 0, form.draw.data or 0, form.away_win.data or 0,
            form.over_15.data or 0, form.over_25.data or 0,
            form.cards.data or 0, form.corners.data or 0,
            form.accuracy.data or 0, form.details.data,
            match_id
        ))
        conn.commit()
        flash('Partida atualizada!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Edit match error: {str(e)}")
        flash('Erro ao editar', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            return_db(conn)

@app.route('/admin/subscriptions')
@admin_required
def admin_subscriptions():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            SELECT s.id, u.email, s.subscription_type, s.expiry_date, s.is_active
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.expiry_date DESC
        ''')
        subscriptions = [dict(zip(
            ['id', 'email', 'type', 'expiry_date', 'is_active'],
            row
        )) for row in cur.fetchall()]
        
        return render_template('admin_subscriptions.html', 
                            subscriptions=subscriptions)
    except Exception as e:
        logger.error(f"Subscriptions error: {str(e)}")
        return render_template('admin_subscriptions.html', 
                            subscriptions=[])
    finally:
        if conn:
            return_db(conn)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu do sistema', 'info')
    return redirect(url_for('index'))

# Inicialização do Banco
def init_db():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Tabela de usuários
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de partidas
        cur.execute('''
            CREATE TABLE IF NOT EXISTS matches (
                id SERIAL PRIMARY KEY,
                home_team TEXT NOT NULL,
                away_team TEXT NOT NULL,
                match_date DATE NOT NULL,
                match_time TIME NOT NULL,
                home_win INTEGER DEFAULT 0,
                draw INTEGER DEFAULT 0,
                away_win INTEGER DEFAULT 0,
                over_15 INTEGER DEFAULT 0,
                over_25 INTEGER DEFAULT 0,
                cards FLOAT DEFAULT 0,
                corners FLOAT DEFAULT 0,
                accuracy INTEGER DEFAULT 0,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de assinaturas
        cur.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                subscription_type TEXT NOT NULL,
                expiry_date DATE NOT NULL,
                is_active BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        logger.info("Banco de dados inicializado")
    except Exception as e:
        logger.error(f"Erro na inicialização: {str(e)}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            return_db(conn)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))