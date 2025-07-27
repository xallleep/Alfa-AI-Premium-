import os
import sys
from datetime import datetime, timezone, timedelta
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from bleach import clean
import hashlib
from flask_minify import Minify
from urllib.parse import urlparse
import re
import pytz
from typing import Optional, List
from flask_caching import Cache
from flask_talisman import Talisman
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from dotenv import load_dotenv
import requests
from requests.exceptions import RequestException

# =============================================
# INITIAL CONFIGURATION
# =============================================

load_dotenv()

# Sentry Configuration (opcional)
if os.environ.get('SENTRY_DSN'):
    sentry_sdk.init(
        dsn=os.environ['SENTRY_DSN'],
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0,
        environment=os.environ.get('FLASK_ENV', 'production')
    )

class Config:
    # Required configurations
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', 'dev-csrf-key')
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    TEMPLATES_AUTO_RELOAD = False
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB (reduzido para Starter)
    
    # Cache settings (simplificado)
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Admin settings
    ADMIN_USERNAME = 'admin_futbolytics'
    ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
    
    # Payment links (exemplo)
    PAGBANK_LINKS = {
        'monthly': os.environ.get('PAGBANK_MONTHLY_LINK', '#'),
        'yearly': os.environ.get('PAGBANK_YEARLY_LINK', '#')
    }

# =============================================
# APP INITIALIZATION (ADAPTADO PARA STARTER)
# =============================================

app = Flask(__name__)
app.config.from_object(Config)

# Security (adaptado para desenvolvimento)
if os.environ.get('FLASK_ENV') == 'production':
    Talisman(app, force_https=True, strict_transport_security=True)
else:
    Talisman(app, force_https=False)

# Cache (simplificado)
cache = Cache(app)

# Optimization
Minify(app=app, html=True, js=True, cssless=True)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiter (memory-based para Starter)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

# Logging configuration (simplificado)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s : %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('futbolytics.render')

# =============================================
# HELPER FUNCTIONS (OTIMIZADAS)
# =============================================

def send_email(subject: str, body: str, recipient: Optional[str] = None) -> bool:
    """Função simulada para evitar dependências externas no Starter"""
    logger.info(f"Email simulador: Para: {recipient}, Assunto: {subject}, Corpo: {body[:100]}...")
    return True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page', 'warning')
            return redirect(url_for('user_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Restricted to administrators', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def sanitize_input(input_str: str, allowed_tags: List[str] = []) -> str:
    """Sanitize user input to prevent XSS"""
    if not input_str:
        return ''
    
    cleaned = clean(input_str, tags=allowed_tags, strip=True)
    cleaned = re.sub(r'[^\w\s@.-]', '', cleaned)
    return cleaned

def format_date(date_str: str, from_format: str = '%Y-%m-%d', to_format: str = '%d/%m/%Y') -> str:
    """Format dates to Brazilian standard"""
    try:
        date_obj = datetime.strptime(date_str, from_format)
        return date_obj.strftime(to_format)
    except (ValueError, TypeError):
        return date_str

def check_password_strength(password: str) -> bool:
    """Check password strength"""
    if len(password) < 8:  # Reduzido para 8 caracteres para melhor UX
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True  # Removida a exigência de caracteres especiais

def check_premium_status(user_id: int) -> bool:
    """Verifica se o usuário tem assinatura premium ativa"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            SELECT 1 FROM subscriptions 
            WHERE user_id = %s AND is_active = TRUE AND expiry_date >= CURRENT_DATE
            LIMIT 1
        ''', (user_id,))
        return cur.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking premium status: {str(e)}")
        return False
    finally:
        if conn:
            return_db(conn)

# =============================================
# DATABASE FUNCTIONS (OTIMIZADAS)
# =============================================

def get_db_url() -> str:
    """Return properly formatted database connection URL"""
    db_url = Config.DATABASE_URL
    if db_url and db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    return db_url or ''

# Connection pool (reduzido para Starter)
connection_pool = None

def init_connection_pool() -> None:
    """Initialize database connection pool"""
    global connection_pool
    if not connection_pool:
        try:
            connection_pool = SimpleConnectionPool(
                minconn=1,
                maxconn=3,  # Reduzido para 3 conexões
                dsn=get_db_url(),
                connect_timeout=5
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {str(e)}")
            raise

def get_db():
    """Get a connection from the pool"""
    init_connection_pool()
    try:
        conn = connection_pool.getconn()
        conn.autocommit = False
        return conn
    except Exception as e:
        logger.error(f"Failed to get database connection: {str(e)}")
        raise

def return_db(conn) -> None:
    """Return a connection to the pool"""
    if connection_pool and conn:
        try:
            connection_pool.putconn(conn)
        except Exception as e:
            logger.error(f"Error returning connection to pool: {str(e)}")
            try:
                conn.close()
            except:
                pass

def init_db() -> None:
    """Initialize database with required tables"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Matches table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS matches (
                id SERIAL PRIMARY KEY,
                home_team TEXT NOT NULL,
                away_team TEXT NOT NULL,
                competition TEXT,
                location TEXT,
                match_date DATE NOT NULL,
                match_time TIME NOT NULL,
                predicted_score TEXT,
                home_win_percent INTEGER DEFAULT 0,
                draw_percent INTEGER DEFAULT 0,
                away_win_percent INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Users table (simplificada)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_premium BOOLEAN DEFAULT FALSE,
                premium_expiry DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Subscriptions table (simplificada)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                subscription_type TEXT NOT NULL,
                payment_amount REAL NOT NULL,
                expiry_date DATE NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Indexes
        cur.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_matches_date ON matches(match_date)')
        
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            return_db(conn)

# =============================================
# FORMS (SIMPLIFICADAS)
# =============================================

class SubscriptionForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password")
    ])
    subscription_type = HiddenField('Subscription Type', validators=[DataRequired()])
    
    def validate_email(self, field):
        """Validate if email is already in use"""
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM users WHERE email = %s', (field.data,))
            if cur.fetchone():
                raise ValidationError('Email already in use')
        except Exception as e:
            logger.error(f"Email validation error: {str(e)}")
            raise ValidationError('Error checking email')
        finally:
            if conn:
                return_db(conn)

    def validate_password(self, field):
        """Validate password strength"""
        if not check_password_strength(field.data):
            raise ValidationError('Password must contain at least 8 characters, including uppercase, lowercase and numbers')

    def validate_confirm_password(self, field):
        """Validate password confirmation"""
        if field.data != self.password.data:
            raise ValidationError('Passwords do not match')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])

# =============================================
# ROUTES (PRINCIPAIS)
# =============================================

@app.route('/')
@cache.cached(timeout=300)
def home():
    """Public home page"""
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def index():
    """Main dashboard page"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        today = datetime.now(pytz.UTC).strftime('%Y-%m-%d')
        next_week = (datetime.now(pytz.UTC) + timedelta(days=7)).strftime('%Y-%m-%d')
        
        cur.execute('''
            SELECT id, home_team, away_team, match_date, match_time, 
                   predicted_score, home_win_percent, draw_percent, away_win_percent
            FROM matches 
            WHERE match_date BETWEEN %s AND %s
            ORDER BY match_date, match_time
            LIMIT 30
        ''', (today, next_week))
        matches = [dict(row) for row in cur.fetchall()]
        
        for match in matches:
            match['formatted_date'] = format_date(match['match_date'].strftime('%Y-%m-%d'))
        
        return render_template('index.html',
                            matches=matches,
                            is_premium=session.get('is_premium', False))
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return render_template('error.html', message="Error loading data"), 500
    finally:
        if conn:
            return_db(conn)

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    """Premium subscription page"""
    form = SubscriptionForm()
    
    if form.validate_on_submit():
        email = sanitize_input(form.email.data)
        password = form.password.data
        subscription_type = form.subscription_type.data
        
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            
            # Check if user exists
            cur.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
            
            if user:
                if check_password_hash(user['password'], password):
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['is_premium'] = check_premium_status(user['id'])
                    return redirect(Config.PAGBANK_LINKS[subscription_type])
                else:
                    flash('Incorrect password', 'danger')
                    return redirect(url_for('user_login'))
            
            # Create new user
            hashed_password = generate_password_hash(password)
            cur.execute('''
                INSERT INTO users (email, password) 
                VALUES (%s, %s) 
                RETURNING id
            ''', (email, hashed_password))
            user_id = cur.fetchone()[0]
            
            # Record subscription
            expiry_date = datetime.now(pytz.UTC) + timedelta(days=30 if subscription_type == 'monthly' else 365)
            
            cur.execute('''
                INSERT INTO subscriptions (
                    user_id, subscription_type, payment_amount, expiry_date
                ) VALUES (%s, %s, %s, %s)
            ''', (
                user_id, subscription_type, 
                6.99 if subscription_type == 'monthly' else 80.99,
                expiry_date
            ))
            
            conn.commit()
            
            # Set up session
            session['logged_in'] = True
            session['user_id'] = user_id
            session['is_premium'] = False
            
            return redirect(Config.PAGBANK_LINKS[subscription_type])
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Subscription error: {str(e)}")
            flash('Subscription processing error', 'danger')
        finally:
            if conn:
                return_db(conn)
    
    return render_template('premium.html', form=form, pagbank_links=Config.PAGBANK_LINKS)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def user_login():
    """User login page"""
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = sanitize_input(form.email.data)
        password = form.password.data
        
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('''
                SELECT id, password FROM users 
                WHERE email = %s
            ''', (email,))
            user = cur.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['is_premium'] = check_premium_status(user['id'])
                return redirect(url_for('index'))
            else:
                flash('Incorrect email or password', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login error', 'danger')
        finally:
            if conn:
                return_db(conn)
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def admin_login():
    """Admin login"""
    form = AdminLoginForm()
    if form.validate_on_submit():
        if (form.username.data == Config.ADMIN_USERNAME and 
            check_password_hash(Config.ADMIN_PASSWORD_HASH, form.password.data)):
            
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard simplificado"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute('SELECT COUNT(*) FROM users')
        user_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM matches')
        match_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM subscriptions WHERE is_active = TRUE')
        active_subs = cur.fetchone()[0]
        
        return render_template(
            'dashboard.html',
            user_count=user_count,
            match_count=match_count,
            active_subs=active_subs
        )
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        return render_template('error.html', message="Error loading data"), 500
    finally:
        if conn:
            return_db(conn)

# =============================================
# API ROUTES (SIMPLIFICADAS)
# =============================================

@app.route('/api/matches')
@login_required
@cache.cached(timeout=60, query_string=True)
def api_matches():
    """API endpoint for matches"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        date_from = request.args.get('from', datetime.now(pytz.UTC).strftime('%Y-%m-%d'))
        date_to = request.args.get('to', (datetime.now(pytz.UTC) + timedelta(days=7)).strftime('%Y-%m-%d'))
        
        cur.execute('''
            SELECT id, home_team, away_team, match_date, match_time 
            FROM matches 
            WHERE match_date BETWEEN %s AND %s
            ORDER BY match_date, match_time
        ''', (date_from, date_to))
        
        matches = [dict(row) for row in cur.fetchall()]
        for m in matches:
            m['match_date'] = m['match_date'].strftime('%Y-%m-%d')
            m['match_time'] = str(m['match_time'])
        
        return jsonify({
            'status': 'success',
            'data': matches,
            'count': len(matches)
        })
    except Exception as e:
        logger.error(f"API matches error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if conn:
            return_db(conn)

@app.route('/ping')
def ping():
    """Health check endpoint simplificado"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        db_ok = cur.fetchone()[0] == 1
        return jsonify({'status': 'ok', 'database': 'ok'}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'degraded', 'database': 'unavailable'}), 503
    finally:
        if conn:
            return_db(conn)

# =============================================
# ERROR HANDLERS
# =============================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', message="Access denied"), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return render_template('error.html', message="Internal server error"), 500

# =============================================
# INITIALIZATION
# =============================================

with app.app_context():
    try:
        init_db()
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.critical(f"Failed to initialize application: {str(e)}")
        raise

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)