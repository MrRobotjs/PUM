# File: migrations/env.py
import os 
import sys 
import logging
from logging.config import fileConfig

from flask import current_app # Requires an app context to be pushed by Flask-Migrate

from alembic import context

# This is to ensure that the 'app' package can be found by Alembic
# when it's trying to autogenerate migrations or when running them.
# It adds the project's root directory (parent of 'migrations' directory) to the Python path.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import your models here so Alembic autogenerate can see them
# This ensures app.models is loaded. All models should be defined in app/models.py directly
# or imported into app/models.py's __init__.py if models were a sub-package.
from app import models # Assuming your models are in app.models.py and db is defined in app.extensions
from app.extensions import db # Import your db instance directly

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None: 
    fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')


def get_engine():
    # In a Flask app, current_app should be available when Flask-Migrate runs CLI commands
    try:
        # For Flask-SQLAlchemy >= 3
        return current_app.extensions['migrate'].db.engine
    except (TypeError, AttributeError, KeyError): # KeyError if 'migrate' extension not found (should be)
        # Fallback for older versions or different setups if needed, though likely not for this project.
        # If current_app.extensions['migrate'] is not setup, it implies Flask-Migrate itself isn't configured
        # correctly on the app instance passed to it.
        # Directly use the imported db instance's engine
        return db.engine


def get_engine_url():
    try:
        # Ensure we get a URL string, replacing '%' for safe use in config
        return get_engine().url.render_as_string(hide_password=False).replace('%', '%%')
    except AttributeError:
        # If render_as_string is not available or engine is None
        return str(get_engine().url).replace('%', '%%')


# Configure 'sqlalchemy.url' for Alembic using the Flask app's config
# This ensures Alembic uses the same database as your Flask app
if current_app: # Check if current_app is available (it should be for flask db commands)
    config.set_main_option('sqlalchemy.url', get_engine_url())
else:
    # This case should ideally not be hit if Flask-Migrate is invoking env.py
    logger.warning("Flask current_app not available; 'sqlalchemy.url' might not be set from app config.")
    # You might need to set a default or raise an error if current_app is required
    # For SQLite, alembic.ini usually has a fallback like: sqlalchemy.url = sqlite:///yourdatabase.db

target_metadata = db.metadata # Point Alembic to your SQLAlchemy metadata directly from imported db

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url") # Get URL from Alembic config (set above from Flask app)
    context.configure(
        url=url, 
        target_metadata=target_metadata, # Use the direct db.metadata
        literal_binds=True,
        dialect_opts={"paramstyle": "named"} # Good for SQLite
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    def process_revision_directives(context, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    # Get configure_args from Flask-Migrate if available, otherwise provide defaults
    conf_args = {}
    if current_app and 'migrate' in current_app.extensions:
        conf_args = current_app.extensions['migrate'].configure_args
    
    if conf_args.get("process_revision_directives") is None:
        conf_args["process_revision_directives"] = process_revision_directives
    
    # For SQLite, ensure batch mode is handled correctly
    # This is often default for Flask-Migrate with SQLite now
    engine = get_engine()
    if engine.name == 'sqlite':
        conf_args.setdefault('render_as_batch', True)
        # dialect_opts for paramstyle is often set by render_as_batch for SQLite
        # but can be explicit if needed: conf_args.setdefault('dialect_opts', {"paramstyle": "named"})

    connectable = engine

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata, # Use the direct db.metadata
            **conf_args
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()