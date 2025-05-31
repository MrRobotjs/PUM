# config.py (Revised path for DB)
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-override-me'
    # instance folder is at the root of the project, next to app/ and config.py
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLALCHEMY_ECHO = True

    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(basedir, 'instance', 'flask_session')
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True

    SCHEDULER_API_ENABLED = False # True if you want to inspect jobs via API
    APP_NAME = "Plex User Manager"