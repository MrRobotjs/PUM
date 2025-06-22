import os
from app import create_app, db
from app.models import Setting, AdminAccount # Import models that might be needed for initial checks or commands
from flask_migrate import Migrate

# Determine if the app is running inside Docker
# This can be useful for certain configurations, though not strictly needed for this setup yet
# IS_DOCKER = os.environ.get('IS_DOCKER', False)

# Create the Flask app instance.
# The configuration will be loaded from app.config module first,
# then potentially overridden by database settings once the app is initialized.
app = create_app()
migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    """
    Makes additional variables available in the Flask shell context.
    Useful for debugging and managing the app via `flask shell`.
    """
    return {
        'db': db,
        'Setting': Setting,
        'AdminAccount': AdminAccount,
        # Add other models here as you create them and find them useful in the shell
        # 'User': User,
        # 'Invite': Invite,
    }

@app.cli.command("init-db")
def init_db_command():
    """
    Initializes the database: creates tables.
    This is an alternative to using Flask-Migrate for the very first setup,
    though migrations are preferred for ongoing schema changes.
    """
    db.create_all()
    print("Initialized the database.")

@app.cli.command("seed-initial-settings")
def seed_initial_settings_command():
    """
    Seeds initial default settings into the database if they don't exist.
    This should be run after `init-db` or migrations.
    """
    # Example of how you might seed a default setting if needed.
    # Most settings will be created through the setup UI.
    # initial_theme = Setting.query.filter_by(key='DEFAULT_THEME').first()
    # if not initial_theme:
    #     default_theme_setting = Setting(key='DEFAULT_THEME', value='light', value_type='string', is_public=True)
    #     db.session.add(default_theme_setting)
    #     db.session.commit()
    #     print("Seeded initial default theme setting.")
    # else:
    #     print("Default theme setting already exists.")
    print("Seed initial settings command - implement as needed.")


if __name__ == '__main__':
    # This is for running with `python run.py` (Flask's development server)
    # For production, Gunicorn is used as defined in the Dockerfile/docker-compose.yml
    # The host '0.0.0.0' makes it accessible externally if not in Docker,
    # or to the mapped port if in Docker.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))