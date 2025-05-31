from app import create_app, db # Import create_app and db instance
from app.models import User, AppSetting, InviteLink, HistoryLog # Import models for shell context
from app.__init__ import initialize_app_services # Import the explicit service initializer

# Get the Flask app instance from the factory
app = create_app()

# Optional: Make db and models available in `flask shell` for easier debugging
@app.shell_context_processor
def make_shell_context():
    return {
        'db': db, 
        'User': User, 
        'AppSetting': AppSetting,
        'InviteLink': InviteLink,
        'HistoryLog': HistoryLog
    }

if __name__ == '__main__':
    # When running directly with `python run.py`:
    # 1. Ensure database migrations are applied.
    # 2. Initialize and start background services.
    # 3. Run the Flask development server.

    with app.app_context(): # Operations like db upgrade need an app context
        from flask_migrate import upgrade
        
        # Apply database migrations
        # This assumes 'migrations' folder exists and is configured.
        # For the very first run, 'flask db init' and 'flask db migrate' must have been done.
        try:
            print("Applying database migrations (if any)...")
            upgrade() # Equivalent to `flask db upgrade`
            print("Database migrations applied.")
        except Exception as e:
            print(f"Error applying database migrations: {e}")
            print("Please ensure migrations are initialized ('flask db init') and generated ('flask db migrate').")
            # Optionally, exit if migrations fail critically, or let app try to start.

        # Initialize and start background services (scheduler, Discord bot)
        # This is called after potential migrations.
        print("Initializing application services (scheduler, Discord bot)...")
        initialize_app_services(app) # Pass the current app instance
        print("Application services initialization triggered.")

    # use_reloader=True is good for development but can cause issues with
    # threaded background tasks or schedulers starting twice.
    # For the Discord bot and APScheduler running in threads, it's often better
    # to set use_reloader=False when testing them, or be aware of potential double-starts.
    # If use_reloader=True, the main process starts, then a child process reloads.
    # Our __init__.py tries to handle this for the bot thread, but it can be tricky.
    # The Docker environment will not use the reloader with Gunicorn.
    print("Starting Flask development server...")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    # Setting use_reloader=False is generally safer when you have background threads
    # like the Discord bot and APScheduler managed by the main Flask process.
    # If you need reloader, test carefully.