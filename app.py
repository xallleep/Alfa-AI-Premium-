import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf.csrf import CSRFProtect

# Configurações básicas
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['DATABASE'] = os.path.join(app.instance_path, 'matches.db')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['WTF_CSRF_ENABLED'] = True

# Solução para o erro do JSONEncoder
import flask.json
import flask_wtf.recaptcha.widgets
flask_wtf.recaptcha.widgets.JSONEncoder = flask.json.JSONEncoder

# Configurações de CSRF
csrf = CSRFProtect(app)

# Configurações de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurações de admin
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123premium')
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

# Decorators
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

# Database helper functions
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    return db

def init_db():
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        db.commit()
        logger.info("Banco de dados inicializado com sucesso")
    except Exception as e:
        logger.error(f"Erro ao inicializar banco de dados: {str(e)}")
        flash('Erro ao inicializar banco de dados', 'danger')
    finally:
        db.close()

# Inicializa o banco de dados
with app.app_context():
    init_db()

# Helper functions
def format_date(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
    except ValueError:
        return date_str

# Rotas principais
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
                            is_premium=True)
    except Exception as e:
        logger.error(f"Erro na rota index: {str(e)}")
        return render_template('error.html', message="Erro ao carregar dados"), 500
    finally:
        db.close()

@app.route('/premium')
def premium_subscription():
    return render_template('premium.html')

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['is_premium'] = user['is_premium']
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('index'))
            else:
                flash('E-mail ou senha incorretos', 'danger')
        except Exception as e:
            logger.error(f"Erro no login: {str(e)}")
            flash('Erro ao realizar login', 'danger')
        finally:
            db.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            flash('Login de administrador realizado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Credenciais de administrador incorretas', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Você foi desconectado como administrador', 'info')
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
        return render_template('dashboard.html', matches=matches)
    except Exception as e:
        logger.error(f"Erro no dashboard admin: {str(e)}")
        return render_template('error.html', message="Erro ao carregar dashboard"), 500
    finally:
        db.close()

@app.route('/admin/match/add', methods=['GET', 'POST'])
@admin_required
def add_match():
    if request.method == 'POST':
        try:
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                request.form.get('home_team'),
                request.form.get('away_team'),
                request.form.get('competition'),
                request.form.get('location'),
                request.form.get('match_date'),
                request.form.get('match_time'),
                request.form.get('predicted_score'),
                request.form.get('home_win_percent', 0),
                request.form.get('away_win_percent', 0),
                request.form.get('draw_percent', 0),
                request.form.get('over_05_percent', 0),
                request.form.get('over_15_percent', 0),
                request.form.get('over_25_percent', 0),
                request.form.get('over_35_percent', 0),
                request.form.get('btts_percent', 0),
                request.form.get('btts_no_percent', 0),
                request.form.get('yellow_cards_predicted', 0),
                request.form.get('red_cards_predicted', 0),
                request.form.get('corners_predicted', 0),
                request.form.get('corners_home_predicted', 0),
                request.form.get('corners_away_predicted', 0),
                request.form.get('possession_home', 50),
                request.form.get('possession_away', 50),
                request.form.get('shots_on_target_home', 0),
                request.form.get('shots_on_target_away', 0),
                request.form.get('shots_off_target_home', 0),
                request.form.get('shots_off_target_away', 0),
                request.form.get('fouls_home', 0),
                request.form.get('fouls_away', 0),
                request.form.get('offsides_home', 0),
                request.form.get('offsides_away', 0),
                request.form.get('safe_prediction', ''),
                request.form.get('risk_prediction', ''),
                request.form.get('details', ''),
                request.form.get('display_order', 0),
                request.form.get('color_scheme', 'blue')
            ))
            db.commit()
            flash('Partida adicionada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            logger.error(f"Erro ao adicionar partida: {str(e)}")
            flash('Erro ao adicionar partida', 'danger')
        finally:
            db.close()
    
    return render_template('admin/add_match.html')

@app.route('/admin/match/edit/<int:match_id>', methods=['GET', 'POST'])
@admin_required
def edit_match(match_id):
    try:
        db = get_db()
        
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
                request.form.get('home_win_percent', 0),
                request.form.get('away_win_percent', 0),
                request.form.get('draw_percent', 0),
                request.form.get('over_05_percent', 0),
                request.form.get('over_15_percent', 0),
                request.form.get('over_25_percent', 0),
                request.form.get('over_35_percent', 0),
                request.form.get('btts_percent', 0),
                request.form.get('btts_no_percent', 0),
                request.form.get('yellow_cards_predicted', 0),
                request.form.get('red_cards_predicted', 0),
                request.form.get('corners_predicted', 0),
                request.form.get('corners_home_predicted', 0),
                request.form.get('corners_away_predicted', 0),
                request.form.get('possession_home', 50),
                request.form.get('possession_away', 50),
                request.form.get('shots_on_target_home', 0),
                request.form.get('shots_on_target_away', 0),
                request.form.get('shots_off_target_home', 0),
                request.form.get('shots_off_target_away', 0),
                request.form.get('fouls_home', 0),
                request.form.get('fouls_away', 0),
                request.form.get('offsides_home', 0),
                request.form.get('offsides_away', 0),
                request.form.get('safe_prediction', ''),
                request.form.get('risk_prediction', ''),
                request.form.get('details', ''),
                request.form.get('display_order', 0),
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
            
        return render_template('edit_match.html', match=match)
    except Exception as e:
        logger.error(f"Erro ao editar partida: {str(e)}")
        flash('Erro ao editar partida', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/match/delete/<int:match_id>', methods=['POST'])
@admin_required
def delete_match(match_id):
    try:
        db = get_db()
        db.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        db.commit()
        flash('Partida excluída com sucesso', 'success')
    except Exception as e:
        logger.error(f"Erro ao excluir partida: {str(e)}")
        flash('Erro ao excluir partida', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    password = request.form.get('password')
    subscription_type = request.form.get('subscription_type')
    
    try:
        db = get_db()
        
        # Verifica se o usuário já existe
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            flash('Este e-mail já está cadastrado', 'danger')
            return redirect(url_for('premium_subscription'))
        
        # Cria novo usuário
        hashed_password = generate_password_hash(password)
        db.execute('INSERT INTO users (email, password, is_premium) VALUES (?, ?, ?)',
                  (email, hashed_password, True))
        
        # Adiciona assinatura
        user_id = db.lastrowid
        payment_date = datetime.now().strftime('%Y-%m-%d')
        
        if subscription_type == 'monthly':
            expiry_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
            payment_amount = 6.99
        else:
            expiry_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
            payment_amount = 80.99
        
        db.execute('''
            INSERT INTO subscriptions (user_id, subscription_type, payment_amount, payment_date, expiry_date)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, subscription_type, payment_amount, payment_date, expiry_date))
        
        db.commit()
        
        # Loga o usuário automaticamente
        session['logged_in'] = True
        session['user_id'] = user_id
        session['is_premium'] = True
        
        flash('Assinatura realizada com sucesso!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Erro ao processar assinatura: {str(e)}")
        flash('Erro ao processar assinatura', 'danger')
        return redirect(url_for('premium_subscription'))
    finally:
        db.close()

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Página não encontrada"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', message="Erro interno do servidor"), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)