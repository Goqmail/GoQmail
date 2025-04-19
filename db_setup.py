#!/usr/bin/env python3
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from flask_session import Session
import os
import logging
import tempfile

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

# Create the Flask application
app = Flask(__name__)
# Ensure we have a consistent session secret key
if "SESSION_SECRET" not in os.environ:
    os.environ["SESSION_SECRET"] = os.urandom(24).hex()

app.secret_key = os.environ.get("SESSION_SECRET")

# Configure session settings for more reliable state management
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions in files
app.config['SESSION_FILE_DIR'] = os.path.join(tempfile.gettempdir(), 'flask_session')  # Session directory
app.config['SESSION_PERMANENT'] = True    # Make sessions persistent
app.config['SESSION_USE_SIGNER'] = True   # Sign the cookies
app.config['SESSION_COOKIE_SECURE'] = False # Allow HTTP (more compatible)
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 # Session timeout in seconds (24 hours)

# Create session directory if it doesn't exist
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# Initialize Flask-Session
Session(app)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'index'