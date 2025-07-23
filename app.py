import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Email
import json

# Configurações básicas com CSRF habilitado
app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(32).hex()),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', os.urandom(32).hex()),
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hora de validade
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    TEMPLATES_AUTO_RELOAD=True,
    DATABASE=os.path.join(app.instance_path, 'matches.db')
)

csrf = CSRFProtect(app)

PAGBANK_LINKS = {
    'monthly': 'https://pag.ae/7_TnPtRxH',
    'yearly': 'https://pag.ae/7_TnQbYun'
}

class SubscriptionForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    subscription_type = HiddenField('Subscription Type', validators=[DataRequired()])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class FlaskJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, '__html__'):
            return str(o.__html__())
        return super().default(o)

app.json_encoder = FlaskJSONEncoder

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123premium')
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

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

def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    return db

def init_db():
    db = None
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
        flash('Database initialization error', 'danger')
    finally:
        if db:
            db.close()

with app.app_context():
    init_db()

def format_date(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
    except (ValueError, TypeError):
        return date_str

def check_premium_status(user_id):
    db = get_db()
    try:
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user and user['is_premium'] and user['premium_expiry']:
            expiry_date = datetime.strptime(user['premium_expiry'], '%Y-%m-%d')
            if expiry_date >= datetime.now():
                return True
        return False
    finally:
        db.close()

def get_numeric_value(key, default=0):
    value = request.form.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def get_float_value(key, default=0.0):
    value = request.form.get(key)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

@app.route('/')
@login_required
def index():
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
    form = SubscriptionForm()
    if form.validate_on_submit():
        try:
            return redirect(url_for('subscribe'))
        except Exception as e:
            logger.error(f"Subscription error: {str(e)}")
            flash('Erro ao processar assinatura. Por favor, tente novamente.', 'danger')
            return redirect(url_for('premium_subscription'))
    
    return render_template('premium.html', form=form, pagbank_links=PAGBANK_LINKS)

@app.route('/subscribe', methods=['POST'])
def subscribe():
    form = SubscriptionForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
        return redirect(url_for('premium_subscription'))
    
    email = form.email.data
    password = form.password.data
    subscription_type = form.subscription_type.data
    
    if subscription_type not in PAGBANK_LINKS:
        flash('Tipo de assinatura inválido', 'danger')
        return redirect(url_for('premium_subscription'))
    
    db = get_db()
    try:
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            flash('Este email já está cadastrado. Por favor, faça login.', 'warning')
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
        
        return redirect(PAGBANK_LINKS[subscription_type])
        
    except sqlite3.IntegrityError:
        db.rollback()
        flash('Erro ao criar conta. Este email já está em uso.', 'danger')
        return redirect(url_for('premium_subscription'))
    except Exception as e:
        db.rollback()
        logger.error(f"Erro no processamento da assinatura: {str(e)}")
        flash('Erro ao processar sua assinatura. Por favor, tente novamente.', 'danger')
        return redirect(url_for('premium_subscription'))
    finally:
        db.close()

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['is_premium'] = check_premium_status(user['id'])
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Incorrect email or password', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login error', 'danger')
        finally:
            db.close()
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Incorrect admin credentials', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        db = get_db()
        matches = db.execute('SELECT * FROM matches ORDER BY match_date, match_time').fetchall()
        return render_template('admin/dashboard.html', matches=matches)
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        return render_template('error.html', message="Error loading dashboard"), 500
    finally:
        db.close()

@app.route('/admin/match/add', methods=['GET', 'POST'])
@admin_required
def add_match():
    if request.method == 'POST':
        db = get_db()
        try:
            home_team = request.form.get('home_team', '').strip()
            away_team = request.form.get('away_team', '').strip()
            match_date = request.form.get('match_date', '').strip()
            match_time = request.form.get('match_time', '').strip()
            if not home_team or not away_team or not match_date or not match_time:
                flash('Fill all required fields', 'danger')
                return redirect(url_for('add_match'))
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
                request.form.get('competition', ''),
                request.form.get('location', ''),
                match_date,
                match_time,
                request.form.get('predicted_score', ''),
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
                request.form.get('safe_prediction', ''),
                request.form.get('risk_prediction', ''),
                request.form.get('details', ''),
                get_numeric_value('display_order'),
                request.form.get('color_scheme', 'blue')
            ))
            db.commit()
            flash('Match added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.rollback()
            logger.error(f"Error adding match: {str(e)}")
            flash('Error adding match', 'danger')
            return redirect(url_for('add_match'))
        finally:
            db.close()
    return render_template('admin/add_match.html')

@app.route('/admin/match/edit/<int:match_id>', methods=['GET', 'POST'])
@admin_required
def edit_match(match_id):
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
                request.form.get('safe_prediction', ''),
                request.form.get('risk_prediction', ''),
                request.form.get('details', ''),
                get_numeric_value('display_order'),
                request.form.get('color_scheme', 'blue'),
                match_id
            ))
            db.commit()
            flash('Match updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        match = db.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
        if not match:
            flash('Match not found', 'danger')
            return redirect(url_for('admin_dashboard'))
        return render_template('admin/edit_match.html', match=match)
    except Exception as e:
        logger.error(f"Error editing match: {str(e)}")
        flash('Error editing match', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/match/delete/<int:match_id>', methods=['POST'])
@admin_required
def delete_match(match_id):
    db = get_db()
    try:
        db.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        db.commit()
        flash('Match deleted successfully', 'success')
    except Exception as e:
        logger.error(f"Error deleting match: {str(e)}")
        flash('Error deleting match', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/payment/verify', methods=['GET', 'POST'])
def payment_verify():
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if not user:
                flash('Email not found', 'danger')
                return redirect(url_for('payment_verify'))
            recent_payments = db.execute('''
                SELECT * FROM subscriptions 
                WHERE user_id = ? 
                AND payment_date >= datetime('now', '-30 minutes')
                ORDER BY payment_date DESC
                LIMIT 1
            ''', (user['id'],)).fetchone()
            if recent_payments:
                db.execute('''
                    UPDATE users SET 
                        is_premium = 1,
                        premium_expiry = ?
                    WHERE id = ?
                ''', (recent_payments['expiry_date'], user['id']))
                db.execute('''
                    UPDATE subscriptions SET 
                        is_active = 1,
                        status = 'completed'
                    WHERE id = ?
                ''', (recent_payments['id'],))
                db.commit()
                flash('Payment confirmed! Premium access activated.', 'success')
                return redirect(url_for('index'))
            else:
                flash('No recent payment found for this email', 'warning')
                return redirect(url_for('payment_verify'))
        except Exception as e:
            logger.error(f"Payment verification error: {str(e)}")
            flash('Payment verification error', 'danger')
            return redirect(url_for('payment_verify'))
        finally:
            db.close()
    return render_template('payment_verify.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', message="Internal server error"), 500

@app.after_request
def log_csrf(response):
    if request.method == 'POST':
        app.logger.debug(f"CSRF Token: {request.form.get('csrf_token')}")
        app.logger.debug(f"Session CSRF: {session.get('csrf_token')}")
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)