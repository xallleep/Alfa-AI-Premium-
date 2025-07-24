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

# Configurações otimizadas para o Render Free Tier
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
    LOG_LEVEL=logging.INFO
)

# Proteção CSRF
csrf = CSRFProtect(app)

# Links de pagamento
PAGBANK_LINKS = {
    'monthly': 'https://pag.ae/7_TnPtRxH',
    'yearly': 'https://pag.ae/7_TnQbYun'
}

# Constantes
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123premium')
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)
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
    subscription_type = HiddenField