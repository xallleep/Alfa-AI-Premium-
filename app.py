import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps

# Configurações básicas
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-123-premium-456')
app.config['DATABASE'] = os.path.join(app.instance_path, 'matches.db')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Configurações de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurações de admin
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = generate_password_hash(os.environ.get('ADMIN_PASS', 'admin123premium'))

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Acesso restrito a administradores', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('premium_user'):
            flash('Conteúdo exclusivo para assinantes Premium', 'warning')
            return redirect(url_for('premium_subscription'))
        return f(*args, **kwargs)
    return decorated_function

# Database helper functions
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        db = get_db()
        
        # Tabela de partidas
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
        
        # Tabela de usuários (simplificada para demo)
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
        
        db.commit()
        logger.info("Banco de dados inicializado com sucesso")
    except Exception as e:
        logger.error(f"Erro ao inicializar banco de dados: {str(e)}")
        raise
    finally:
        db.close()

# Inicializa o banco de dados
with app.app_context():
    init_db()

# Helper functions
def format_date(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
    except:
        return date_str

# Rotas principais
@app.route('/')
def index():
    try:
        db = get_db()
        
        # Pega apenas jogos dos próximos 7 dias para otimização
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
                            is_premium=session.get('premium_user', False))
    except Exception as e:
        logger.error(f"Erro na rota index: {str(e)}")
        return render_template('error.html', message="Erro ao carregar dados"), 500

@app.route('/premium')
def premium_subscription():
    return render_template('premium.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    sub_type = request.form.get('subscription_type')
    
    # Simulação de pagamento - em produção integrar com gateway de pagamento
    if sub_type == 'monthly':
        session['premium_user'] = True
        session['premium_expiry'] = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
        flash('Assinatura mensal ativada por R$6,99!', 'success')
    elif sub_type == 'yearly':
        session['premium_user'] = True
        session['premium_expiry'] = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
        flash('Assinatura anual ativada por R$80,99!', 'success')
    
    return redirect(url_for('index'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if (request.form['username'] == ADMIN_USER and 
            check_password_hash(ADMIN_PASS, request.form['password'])):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Credenciais inválidas', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    db = get_db()
    matches = db.execute('SELECT * FROM matches ORDER BY match_date DESC LIMIT 50').fetchall()
    db.close()
    return render_template('admin/dashboard.html', matches=matches)

@app.route('/admin/matches/add', methods=['GET', 'POST'])
@login_required
def add_match():
    if request.method == 'POST':
        try:
            db = get_db()
            db.execute('''
                INSERT INTO matches (
                    home_team, away_team, competition, location, match_date, match_time,
                    predicted_score, home_win_percent, draw_percent, away_win_percent,
                    over_15_percent, over_25_percent, btts_percent, yellow_cards_predicted,
                    red_cards_predicted, corners_predicted, possession_home, possession_away,
                    shots_on_target_home, shots_on_target_away, details, display_order, color_scheme
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                request.form['home_team'], request.form['away_team'],
                request.form.get('competition'), request.form.get('location'),
                request.form['match_date'], request.form['match_time'],
                request.form.get('predicted_score'), 
                request.form.get('home_win_percent', 0),
                request.form.get('draw_percent', 0),
                request.form.get('away_win_percent', 0),
                request.form.get('over_15_percent', 0),
                request.form.get('over_25_percent', 0),
                request.form.get('btts_percent', 0),
                request.form.get('yellow_cards_predicted', 0),
                request.form.get('red_cards_predicted', 0),
                request.form.get('corners_predicted', 0),
                request.form.get('possession_home', 50),
                request.form.get('possession_away', 50),
                request.form.get('shots_on_target_home', 0),
                request.form.get('shots_on_target_away', 0),
                request.form.get('details'),
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

@app.route('/admin/matches/<int:match_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_match(match_id):
    db = get_db()
    match = db.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
    
    if request.method == 'POST':
        try:
            db.execute('''
                UPDATE matches SET
                    home_team = ?, away_team = ?, competition = ?, location = ?,
                    match_date = ?, match_time = ?, predicted_score = ?,
                    home_win_percent = ?, draw_percent = ?, away_win_percent = ?,
                    over_15_percent = ?, over_25_percent = ?, btts_percent = ?,
                    yellow_cards_predicted = ?, red_cards_predicted = ?,
                    corners_predicted = ?, possession_home = ?, possession_away = ?,
                    shots_on_target_home = ?, shots_on_target_away = ?,
                    details = ?, display_order = ?, color_scheme = ?
                WHERE id = ?
            ''', (
                request.form['home_team'], request.form['away_team'],
                request.form.get('competition'), request.form.get('location'),
                request.form['match_date'], request.form['match_time'],
                request.form.get('predicted_score'),
                request.form.get('home_win_percent', 0),
                request.form.get('draw_percent', 0),
                request.form.get('away_win_percent', 0),
                request.form.get('over_15_percent', 0),
                request.form.get('over_25_percent', 0),
                request.form.get('btts_percent', 0),
                request.form.get('yellow_cards_predicted', 0),
                request.form.get('red_cards_predicted', 0),
                request.form.get('corners_predicted', 0),
                request.form.get('possession_home', 50),
                request.form.get('possession_away', 50),
                request.form.get('shots_on_target_home', 0),
                request.form.get('shots_on_target_away', 0),
                request.form.get('details'),
                request.form.get('display_order', 0),
                request.form.get('color_scheme', 'blue'),
                match_id
            ))
            db.commit()
            flash('Partida atualizada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            logger.error(f"Erro ao atualizar partida: {str(e)}")
            flash('Erro ao atualizar partida', 'danger')
        finally:
            db.close()
    
    return render_template('admin/edit_match.html', match=match)

@app.route('/admin/matches/<int:match_id>/delete', methods=['POST'])
@login_required
def delete_match(match_id):
    try:
        db = get_db()
        db.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        db.commit()
        flash('Partida removida com sucesso!', 'success')
    except Exception as e:
        logger.error(f"Erro ao remover partida: {str(e)}")
        flash('Erro ao remover partida', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_dashboard'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Página não encontrada"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', message="Erro interno do servidor"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))