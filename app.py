from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from flask_wtf import CSRFProtect
from wtforms import Form, StringField, PasswordField, HiddenField, validators
import os

app = Flask(__name__)

# Configuração básica
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'uma-chave-secreta-aleatoria-123'),
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', 'outra-chave-secreta-456'),
    DATABASE=os.path.join(app.instance_path, 'database.db'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
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
    'password_hash': generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
}

# Formulários
class SubscriptionForm(Form):
    email = StringField('Email', validators=[
        validators.DataRequired(),
        validators.Email(),
        validators.Length(min=6, max=50)
    ])
    password = PasswordField('Senha', validators=[
        validators.DataRequired(),
        validators.Length(min=6)
    ])
    subscription_type = HiddenField('Tipo de Assinatura', validators=[
        validators.DataRequired()
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
        cursor = db.cursor()
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    is_premium BOOLEAN DEFAULT 0,
                    premium_expiry TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
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
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    home_team TEXT NOT NULL,
                    away_team TEXT NOT NULL,
                    competition TEXT,
                    location TEXT,
                    match_date TEXT NOT NULL,
                    match_time TEXT NOT NULL,
                    predicted_score TEXT,
                    home_win_percent REAL DEFAULT 0,
                    away_win_percent REAL DEFAULT 0,
                    draw_percent REAL DEFAULT 0,
                    over_05_percent REAL DEFAULT 0,
                    over_15_percent REAL DEFAULT 0,
                    over_25_percent REAL DEFAULT 0,
                    over_35_percent REAL DEFAULT 0,
                    btts_percent REAL DEFAULT 0,
                    btts_no_percent REAL DEFAULT 0,
                    yellow_cards_predicted REAL DEFAULT 0,
                    red_cards_predicted REAL DEFAULT 0,
                    corners_predicted REAL DEFAULT 0,
                    corners_home_predicted REAL DEFAULT 0,
                    corners_away_predicted REAL DEFAULT 0,
                    possession_home REAL DEFAULT 50,
                    possession_away REAL DEFAULT 50,
                    shots_on_target_home INTEGER DEFAULT 0,
                    shots_on_target_away INTEGER DEFAULT 0,
                    shots_off_target_home INTEGER DEFAULT 0,
                    shots_off_target_away INTEGER DEFAULT 0,
                    fouls_home INTEGER DEFAULT 0,
                    fouls_away INTEGER DEFAULT 0,
                    offsides_home INTEGER DEFAULT 0,
                    offsides_away INTEGER DEFAULT 0,
                    details TEXT,
                    safe_prediction TEXT,
                    risk_prediction TEXT,
                    display_order INTEGER DEFAULT 0,
                    color_scheme TEXT DEFAULT 'blue',
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
            flash('Por favor, faça login para acessar esta página', 'warning')
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
        if not session.get('is_admin'):
            flash('Acesso restrito a administradores', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Rotas Públicas
@app.route('/')
def home():
    """Rota principal que redireciona para a página de assinatura"""
    return redirect(url_for('premium_subscription'))

@app.route('/premium', methods=['GET', 'POST'])
def premium_subscription():
    """Página de assinatura premium"""
    form = SubscriptionForm(request.form if request.method == 'POST' else None)
    
    if request.method == 'POST' and form.validate():
        db = None
        try:
            db = get_db()
            cursor = db.cursor()
            email = form.email.data.lower().strip()
            password = form.password.data
            subscription_type = form.subscription_type.data
            
            if subscription_type not in PAGBANK_LINKS:
                flash('Tipo de assinatura inválido', 'danger')
                return redirect(url_for('premium_subscription'))
            
            # Verifica se usuário já existe
            user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
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
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_pw))
            user_id = cursor.lastrowid
            
            # Configura assinatura
            payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if subscription_type == 'monthly':
                expiry_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
                amount = 6.99
            else:
                expiry_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
                amount = 80.99
            
            cursor.execute('''
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
    
    return render_template('premium.html', form=form, datetime=datetime)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    """Página de login de usuário"""
    form = LoginForm(request.form if request.method == 'POST' else None)
    
    if request.method == 'POST' and form.validate():
        db = None
        try:
            db = get_db()
            cursor = db.cursor()
            email = form.email.data.lower().strip()
            user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
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
    
    return render_template('login.html', form=form, datetime=datetime)

@app.route('/logout')
def logout():
    """Encerra a sessão do usuário"""
    session.clear()
    flash('Você foi desconectado com sucesso', 'info')
    return redirect(url_for('home'))

@app.route('/payment/verify', methods=['GET', 'POST'])
def payment_verify():
    """Página de verificação de pagamento"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Por favor, informe seu email', 'danger')
            return redirect(url_for('payment_verify'))
        
        db = None
        try:
            db = get_db()
            cursor = db.cursor()
            user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if not user:
                flash('Email não encontrado', 'danger')
                return redirect(url_for('payment_verify'))
            
            subscription = cursor.execute('''
                SELECT * FROM subscriptions 
                WHERE user_id = ? 
                ORDER BY payment_date DESC 
                LIMIT 1
            ''', (user['id'],)).fetchone()
            
            if subscription:
                cursor.execute('''
                    UPDATE users SET 
                        is_premium = 1,
                        premium_expiry = ?
                    WHERE id = ?
                ''', (subscription['expiry_date'], user['id']))
                
                cursor.execute('''
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
    
    return render_template('payment_verify.html', datetime=datetime)

# Rotas Admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if (username == ADMIN_CREDENTIALS['username'] and 
            check_password_hash(ADMIN_CREDENTIALS['password_hash'], password)):
            session['admin_logged_in'] = True
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Credenciais inválidas', 'danger')
    
    return render_template('admin/login.html', datetime=datetime)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        matches = cursor.execute('SELECT * FROM matches ORDER BY match_date, match_time').fetchall()
        return render_template('admin/dashboard.html', matches=matches, datetime=datetime)
    except Exception as e:
        logger.error(f"Erro no dashboard admin: {e}")
        flash('Ocorreu um erro ao carregar o painel administrativo', 'danger')
        return redirect(url_for('home'))
    finally:
        if db:
            db.close()

@app.route('/admin/matches/add', methods=['GET', 'POST'])
@admin_required
def add_match():
    if request.method == 'POST':
        db = None
        try:
            db = get_db()
            cursor = db.cursor()
            # Coletar todos os dados do formulário
            match_data = {
                'home_team': request.form['home_team'],
                'away_team': request.form['away_team'],
                'competition': request.form.get('competition', ''),
                'location': request.form.get('location', ''),
                'match_date': request.form['match_date'],
                'match_time': request.form['match_time'],
                'predicted_score': request.form.get('predicted_score', ''),
                'home_win_percent': float(request.form.get('home_win_percent', 0)),
                'away_win_percent': float(request.form.get('away_win_percent', 0)),
                'draw_percent': float(request.form.get('draw_percent', 0)),
                'over_05_percent': float(request.form.get('over_05_percent', 0)),
                'over_15_percent': float(request.form.get('over_15_percent', 0)),
                'over_25_percent': float(request.form.get('over_25_percent', 0)),
                'over_35_percent': float(request.form.get('over_35_percent', 0)),
                'btts_percent': float(request.form.get('btts_percent', 0)),
                'btts_no_percent': float(request.form.get('btts_no_percent', 0)),
                'yellow_cards_predicted': float(request.form.get('yellow_cards_predicted', 0)),
                'red_cards_predicted': float(request.form.get('red_cards_predicted', 0)),
                'corners_predicted': float(request.form.get('corners_predicted', 0)),
                'corners_home_predicted': float(request.form.get('corners_home_predicted', 0)),
                'corners_away_predicted': float(request.form.get('corners_away_predicted', 0)),
                'possession_home': float(request.form.get('possession_home', 50)),
                'possession_away': float(request.form.get('possession_away', 50)),
                'shots_on_target_home': int(request.form.get('shots_on_target_home', 0)),
                'shots_on_target_away': int(request.form.get('shots_on_target_away', 0)),
                'shots_off_target_home': int(request.form.get('shots_off_target_home', 0)),
                'shots_off_target_away': int(request.form.get('shots_off_target_away', 0)),
                'fouls_home': int(request.form.get('fouls_home', 0)),
                'fouls_away': int(request.form.get('fouls_away', 0)),
                'offsides_home': int(request.form.get('offsides_home', 0)),
                'offsides_away': int(request.form.get('offsides_away', 0)),
                'details': request.form.get('details', ''),
                'safe_prediction': request.form.get('safe_prediction', ''),
                'risk_prediction': request.form.get('risk_prediction', ''),
                'display_order': int(request.form.get('display_order', 0)),
                'color_scheme': request.form.get('color_scheme', 'blue')
            }
            
            cursor.execute('''
                INSERT INTO matches (
                    home_team, away_team, competition, location, match_date, match_time,
                    predicted_score, home_win_percent, away_win_percent, draw_percent,
                    over_05_percent, over_15_percent, over_25_percent, over_35_percent,
                    btts_percent, btts_no_percent, yellow_cards_predicted, red_cards_predicted,
                    corners_predicted, corners_home_predicted, corners_away_predicted,
                    possession_home, possession_away, shots_on_target_home, shots_on_target_away,
                    shots_off_target_home, shots_off_target_away, fouls_home, fouls_away,
                    offsides_home, offsides_away, details, safe_prediction, risk_prediction,
                    display_order, color_scheme
                ) VALUES (
                    :home_team, :away_team, :competition, :location, :match_date, :match_time,
                    :predicted_score, :home_win_percent, :away_win_percent, :draw_percent,
                    :over_05_percent, :over_15_percent, :over_25_percent, :over_35_percent,
                    :btts_percent, :btts_no_percent, :yellow_cards_predicted, :red_cards_predicted,
                    :corners_predicted, :corners_home_predicted, :corners_away_predicted,
                    :possession_home, :possession_away, :shots_on_target_home, :shots_on_target_away,
                    :shots_off_target_home, :shots_off_target_away, :fouls_home, :fouls_away,
                    :offsides_home, :offsides_away, :details, :safe_prediction, :risk_prediction,
                    :display_order, :color_scheme
                )
            ''', match_data)
            
            db.commit()
            flash('Partida adicionada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.rollback()
            logger.error(f"Erro ao adicionar partida: {e}")
            flash('Erro ao adicionar partida', 'danger')
        finally:
            if db:
                db.close()
    
    return render_template('admin/add_match.html', datetime=datetime)

@app.route('/admin/matches/edit/<int:match_id>', methods=['GET', 'POST'])
@admin_required
def edit_match(match_id):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        match = cursor.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
        
        if not match:
            flash('Partida não encontrada', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        if request.method == 'POST':
            try:
                match_data = {
                    'id': match_id,
                    'home_team': request.form['home_team'],
                    'away_team': request.form['away_team'],
                    'competition': request.form.get('competition', ''),
                    'location': request.form.get('location', ''),
                    'match_date': request.form['match_date'],
                    'match_time': request.form['match_time'],
                    'predicted_score': request.form.get('predicted_score', ''),
                    'home_win_percent': float(request.form.get('home_win_percent', 0)),
                    'away_win_percent': float(request.form.get('away_win_percent', 0)),
                    'draw_percent': float(request.form.get('draw_percent', 0)),
                    'over_05_percent': float(request.form.get('over_05_percent', 0)),
                    'over_15_percent': float(request.form.get('over_15_percent', 0)),
                    'over_25_percent': float(request.form.get('over_25_percent', 0)),
                    'over_35_percent': float(request.form.get('over_35_percent', 0)),
                    'btts_percent': float(request.form.get('btts_percent', 0)),
                    'btts_no_percent': float(request.form.get('btts_no_percent', 0)),
                    'yellow_cards_predicted': float(request.form.get('yellow_cards_predicted', 0)),
                    'red_cards_predicted': float(request.form.get('red_cards_predicted', 0)),
                    'corners_predicted': float(request.form.get('corners_predicted', 0)),
                    'corners_home_predicted': float(request.form.get('corners_home_predicted', 0)),
                    'corners_away_predicted': float(request.form.get('corners_away_predicted', 0)),
                    'possession_home': float(request.form.get('possession_home', 50)),
                    'possession_away': float(request.form.get('possession_away', 50)),
                    'shots_on_target_home': int(request.form.get('shots_on_target_home', 0)),
                    'shots_on_target_away': int(request.form.get('shots_on_target_away', 0)),
                    'shots_off_target_home': int(request.form.get('shots_off_target_home', 0)),
                    'shots_off_target_away': int(request.form.get('shots_off_target_away', 0)),
                    'fouls_home': int(request.form.get('fouls_home', 0)),
                    'fouls_away': int(request.form.get('fouls_away', 0)),
                    'offsides_home': int(request.form.get('offsides_home', 0)),
                    'offsides_away': int(request.form.get('offsides_away', 0)),
                    'details': request.form.get('details', ''),
                    'safe_prediction': request.form.get('safe_prediction', ''),
                    'risk_prediction': request.form.get('risk_prediction', ''),
                    'display_order': int(request.form.get('display_order', 0)),
                    'color_scheme': request.form.get('color_scheme', 'blue')
                }
                
                cursor.execute('''
                    UPDATE matches SET
                        home_team = :home_team,
                        away_team = :away_team,
                        competition = :competition,
                        location = :location,
                        match_date = :match_date,
                        match_time = :match_time,
                        predicted_score = :predicted_score,
                        home_win_percent = :home_win_percent,
                        away_win_percent = :away_win_percent,
                        draw_percent = :draw_percent,
                        over_05_percent = :over_05_percent,
                        over_15_percent = :over_15_percent,
                        over_25_percent = :over_25_percent,
                        over_35_percent = :over_35_percent,
                        btts_percent = :btts_percent,
                        btts_no_percent = :btts_no_percent,
                        yellow_cards_predicted = :yellow_cards_predicted,
                        red_cards_predicted = :red_cards_predicted,
                        corners_predicted = :corners_predicted,
                        corners_home_predicted = :corners_home_predicted,
                        corners_away_predicted = :corners_away_predicted,
                        possession_home = :possession_home,
                        possession_away = :possession_away,
                        shots_on_target_home = :shots_on_target_home,
                        shots_on_target_away = :shots_on_target_away,
                        shots_off_target_home = :shots_off_target_home,
                        shots_off_target_away = :shots_off_target_away,
                        fouls_home = :fouls_home,
                        fouls_away = :fouls_away,
                        offsides_home = :offsides_home,
                        offsides_away = :offsides_away,
                        details = :details,
                        safe_prediction = :safe_prediction,
                        risk_prediction = :risk_prediction,
                        display_order = :display_order,
                        color_scheme = :color_scheme
                    WHERE id = :id
                ''', match_data)
                
                db.commit()
                flash('Partida atualizada com sucesso!', 'success')
                return redirect(url_for('admin_dashboard'))
                
            except Exception as e:
                db.rollback()
                logger.error(f"Erro ao atualizar partida: {e}")
                flash('Erro ao atualizar partida', 'danger')
        
        return render_template('admin/edit_match.html', match=match, datetime=datetime)
    
    except Exception as e:
        logger.error(f"Erro ao carregar partida para edição: {e}")
        flash('Erro ao carregar partida', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        if db:
            db.close()

@app.route('/admin/matches/delete/<int:match_id>', methods=['POST'])
@admin_required
def delete_match(match_id):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        db.commit()
        flash('Partida excluída com sucesso', 'success')
    except Exception as e:
        db.rollback()
        logger.error(f"Erro ao excluir partida: {e}")
        flash('Erro ao excluir partida', 'danger')
    finally:
        if db:
            db.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('is_admin', None)
    flash('Você saiu do painel administrativo', 'info')
    return redirect(url_for('home'))

# Rotas Premium
@app.route('/premium/matches')
@login_required
@premium_required
def premium_matches():
    """Página de partidas para usuários premium"""
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Obter partidas de hoje
        today_matches = cursor.execute('''
            SELECT * FROM matches 
            WHERE match_date = ?
            ORDER BY match_time ASC
        ''', (today,)).fetchall()
        
        # Obter próximas partidas
        other_matches = cursor.execute('''
            SELECT * FROM matches 
            WHERE match_date > ?
            ORDER BY match_date ASC, match_time ASC
            LIMIT 50
        ''', (today,)).fetchall()
        
        return render_template('premium_matches.html', 
                            today_matches=today_matches,
                            other_matches=other_matches,
                            last_updated=datetime.now().strftime('%d/%m/%Y %H:%M'),
                            datetime=datetime)
        
    except Exception as e:
        logger.error(f"Erro ao carregar partidas: {e}")
        flash('Ocorreu um erro ao carregar as partidas', 'danger')
        return redirect(url_for('home'))
    finally:
        if db:
            db.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)