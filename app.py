import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps

# Configurações básicas
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['DATABASE'] = os.path.join(app.instance_path, 'matches.db')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['TEMPLATES_AUTO_RELOAD'] = True

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
            return redirect(url_for('admin_login'))
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
                over_15_percent INTEGER DEFAULT 0,
                over_25_percent INTEGER DEFAULT 0,
                btts_percent INTEGER DEFAULT 0,
                yellow_cards_predicted INTEGER DEFAULT 0,
                red_cards_predicted INTEGER DEFAULT 0,
                corners_predicted INTEGER DEFAULT 0,
                possession_home INTEGER DEFAULT 50,
                possession_away INTEGER DEFAULT 50,
                shots_on_target_home INTEGER DEFAULT 0,
                shots_on_target_away INTEGER DEFAULT 0,
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

# Proteção para rotas admin
@app.before_request
def before_request():
    if request.path.startswith('/admin') and not request.path.startswith('/admin/login'):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))

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
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('premium.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    sub_type = request.form.get('subscription_type')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not email or not password:
        flash('Por favor, preencha todos os campos', 'danger')
        return redirect(url_for('premium_subscription'))
    
    try:
        db = get_db()
        
        # Verifica se o usuário já existe
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            flash('Este e-mail já está cadastrado', 'danger')
            return redirect(url_for('premium_subscription'))
        
        # Cria o usuário
        hashed_password = generate_password_hash(password)
        db.execute('INSERT INTO users (email, password, is_premium) VALUES (?, ?, 1)', 
                  (email, hashed_password))
        
        # Adiciona a assinatura
        if sub_type == 'monthly':
            amount = 6.99
            expiry_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
        else:
            amount = 80.99
            expiry_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
            
        user_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        db.execute('''
            INSERT INTO subscriptions 
            (user_id, subscription_type, payment_amount, payment_date, expiry_date)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            user_id,
            sub_type,
            amount,
            datetime.now().strftime('%Y-%m-%d'),
            expiry_date
        ))
        
        db.commit()
        
        session['logged_in'] = True
        session['user_email'] = email
        session['is_premium'] = True
        
        flash('Assinatura realizada com sucesso!', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Erro ao criar assinatura: {str(e)}")
        flash('Erro ao processar assinatura', 'danger')
        return redirect(url_for('premium_subscription'))
    finally:
        db.close()

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
                session['user_email'] = email
                session['is_premium'] = bool(user['is_premium'])
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Credenciais inválidas', 'danger')
                
        except Exception as e:
            logger.error(f"Erro no login: {str(e)}")
            flash('Erro ao processar login', 'danger')
        finally:
            db.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('premium_subscription'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Por favor, preencha todos os campos', 'danger')
            return redirect(url_for('admin_login'))
        
        # Verificação segura com hash
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('Login administrativo realizado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            import time
            time.sleep(1)  # Delay para evitar timing attacks
            flash('Credenciais inválidas', 'danger')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Você foi desconectado', 'info')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        db = get_db()
        matches = db.execute('SELECT * FROM matches ORDER BY match_date DESC LIMIT 50').fetchall()
        users = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        premium_users = db.execute('SELECT COUNT(*) as count FROM users WHERE is_premium = 1').fetchone()['count']
        
        return render_template('admin/dashboard.html', 
                             matches=matches,
                             users=users,
                             premium_users=premium_users)
    except Exception as e:
        logger.error(f"Erro no dashboard admin: {str(e)}")
        flash('Erro ao carregar dados', 'danger')
        return redirect(url_for('admin_login'))
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
                    home_win_percent, away_win_percent, draw_percent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                request.form.get('draw_percent', 0)
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
                    draw_percent = ?
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
        flash('Partida excluída com sucesso!', 'success')
    except Exception as e:
        logger.error(f"Erro ao excluir partida: {str(e)}")
        flash('Erro ao excluir partida', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)