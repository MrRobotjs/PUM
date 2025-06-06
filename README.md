# Plex User Manager (PUM)

Plex User Manager (PUM) is a self-hosted web application designed to streamline the management of your Plex Media Server users. It allows administrators to send targeted invitations with granular control over library access, sync users from their Plex account, and integrate with Discord for enhanced user verification and automated actions.

The application features a web-based admin panel, a step-by-step setup wizard, and Docker support for easy deployment.

Dashboard             |  Invites
:-------------------------:|:-------------------------:
![chrome_YBGsbBoc4z](https://github.com/user-attachments/assets/a3b0da21-2256-4dae-9ec6-90d494d3ca0e)  |  ![chrome_kUMqRmOBQL](https://github.com/user-attachments/assets/a6156cae-bf43-4e72-8ed5-119e09c7673b)
Users             |  Users
![chrome_d2i5NMAD2R](https://github.com/user-attachments/assets/7679fbe7-465d-433c-8cc8-90d4081abbae)  |  ![chrome_E8vCpE37vG](https://github.com/user-attachments/assets/e74254b4-e42e-42f3-8243-532ce249eb69)
History             |  Settings
![chrome_g07LxLgECk](https://github.com/user-attachments/assets/19f86c6e-41ff-49f6-8fd0-00008e6c6b5d)  |  ![chrome_U7txZXcf85](https://github.com/user-attachments/assets/d880a223-c52c-4ed5-a1f1-90efa1b57845)

## Key Features

*   **Admin-Controlled Plex User Invitations:**
    *   Generate unique, time-limited, and usage-capped invite links.
    *   Specify exactly which Plex libraries are shared through each invite link.
*   **Plex User Management:**
    *   Sync users from your Plex account's "Friends" list.
    *   View managed Plex users, their Plex details, and linked Discord information.
    *   Edit user properties, including shared libraries and Discord ID linkage.
    *   Manually remove users from your Plex server and the application.
*   **Discord Integration (Optional but Recommended):**
    *   **SSO Login:** Allow users to "Login with Discord" on invite pages to pre-fill their Discord ID.
    *   **Discord Bot Features:**
        *   Users can request Plex invites via a Discord bot command.
        *   Monitor Discord server membership: automatically remove Plex access if a user leaves the designated Discord server.
        *   Monitor Discord roles: automatically remove Plex access if a user loses a specific "Plex Access" role.
        *   Admin notifications via Discord DM for critical bot errors.
*   **User Activity & Management:**
    *   Track when users were last actively streaming Plex content (feature relies on scheduler task).
    *   Automated purging of inactive users based on configurable criteria (e.g., days inactive, exempting Plex Home users or those sharing back).
    *   Whitelist users from purging.
*   **Admin Interface:**
    *   Dashboard with key statistics (total users, active invites, server status).
    *   Detailed activity history log for all significant application and user events.
    *   Comprehensive settings panel for Plex server connection, application behavior, and Discord integration.
*   **Ease of Use & Deployment:**
    *   Step-by-step web-based setup wizard for initial configuration.
    *   Docker and Docker Compose support for straightforward deployment.
    *   Dark/Light theme toggle for the web interface.
    *   Responsive UI built with Tailwind CSS.

## Tech Stack

*   **Backend:** Python, Flask
*   **Database:** SQLAlchemy (defaults to SQLite, configurable) with Flask-Migrate for migrations.
*   **Scheduling:** APScheduler (for background tasks like Discord checks and log cleanup).
*   **Plex Interaction:** Python PlexAPI library & direct Plex.tv API calls.
*   **Discord Interaction:** discord.py library for bot features, direct Discord API calls for OAuth.
*   **Forms:** Flask-WTF with WTForms for web forms and CSRF protection.
*   **Templating:** Jinja2
*   **Frontend:** Tailwind CSS, Vanilla JavaScript.
*   **Deployment:** Docker, Gunicorn.

## Prerequisites

*   Python 3.9+
*   Node.js and npm (for managing Tailwind CSS dependencies and build process)
*   Docker and Docker Compose (recommended for deployment)
*   A Plex Media Server
*   A Plex account (Plex Pass likely required for inviting users beyond your Plex Home limit)
*   For Discord Features:
    *   A Discord Application created in the Discord Developer Portal.
    *   A Discord Bot token associated with that application.
    *   Relevant Discord Server ID, Channel IDs, Role IDs as configured.

## Setup and Installation

1.  **Clone the Repository:**
    ```bash
    git clone <your_repository_url> pum
    cd pum
    ```

2.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install Node.js Dependencies (for Tailwind CSS):**
    ```bash
    npm install
    ```

4.  **Build CSS:**
    ```bash
    npm run build-css 
    # Or for development: npm run watch-css
    ```

5.  **Configure Environment Variables:**
    *   Copy the example environment file: `cp .env.example .env`
    *   Edit the `.env` file with your specific settings. See "Key Configuration Variables" below.
        *   **Crucially, set a strong `SECRET_KEY`!** You can generate one using `python -c 'import secrets; print(secrets.token_hex(24))'`.
        *   Set your `PLEX_URL` and `PLEX_TOKEN`.
        *   Set `APP_BASE_URL` to the public URL where this application will be accessible (e.g., `http://localhost:5699` for local Docker, or `https://pum.yourdomain.com` for production).

6.  **Database Setup:**
    *   The application uses SQLite by default (`instance/app.db`). Ensure the `instance/` directory is writable.
    *   Apply database migrations:
        ```bash
        flask db upgrade
        ```

7.  **Register Scheduler Jobs (Important for Docker/Gunicorn):**
    This command populates the database with job definitions for APScheduler.
    ```bash
    flask register_jobs_cli
    ```

8.  **Initial Setup Wizard:**
    *   When you first run the application, it should redirect you to the setup wizard (`/setup/wizard`) if setup is not marked as complete.
    *   Follow the on-screen instructions to:
        1.  Create an admin user (username/password or via Plex login).
        2.  Configure Plex server URL, Plex Token, and the Application Base URL.
        3.  Optionally, configure Discord OAuth and Bot settings.

## Running the Application

### Locally with Flask Development Server (for development)

1.  Ensure your `.env` file is configured, especially `FLASK_APP` and `FLASK_DEBUG`.
    Create/edit `.flaskenv`:
    ```
    FLASK_APP=run.py
    FLASK_DEBUG=1
    ```
2.  If you want services like the Discord bot or scheduled tasks to run in this dev mode, you might need to start them separately or use a command like `flask start_services_dev` (if you've kept/implemented such a command for foreground service running). For simple web UI testing:
    ```bash
    flask run --host=0.0.0.0 --port=5000 
    ```
    (The port here is Flask's dev server port, not necessarily the one exposed by Docker later). Access at `http://localhost:5000`.

### Using Docker and Docker Compose (Recommended for Production/Staging)

1.  Ensure Docker and Docker Compose are installed.
2.  Make sure your `.env` file is correctly configured, especially `APP_BASE_URL` (which should be the URL you use to access the app, e.g., `http://localhost:5699` if using the default docker-compose port mapping).
3.  Build and run the containers:
    ```bash
    docker-compose up --build -d
    ```
4.  Access the application at the port specified in your `docker-compose.yml` (default is `http://localhost:5699`).
5.  To view logs:
    ```bash
    docker-compose logs -f pum
    ```
6.  To stop:
    ```bash
    docker-compose down
    ```

## Key Configuration Variables (`.env` file)

*   `SECRET_KEY`: **Required.** A long, random string for session security and CSRF protection.
*   `DATABASE_URL`: Optional. Defaults to SQLite in the `instance` folder (`sqlite:///instance/app.db`). You can change this to use PostgreSQL, MySQL, etc.
*   `FLASK_DEBUG`: Set to `1` for development (enables debug mode, reloader), `0` for production.
*   `LOG_LEVEL`: Set log level for the app. e.g. `INFO`, `DEBUG`, `WARNING`, `ERROR`. (Custom variable, ensure your app uses it if defined).

*   **Plex Settings (Required for core functionality):**
    *   `PLEX_URL`: Full URL to your Plex Media Server (e.g., `http://localhost:32400` or `https://yourplex.domain.com`).
    *   `PLEX_TOKEN`: Your X-Plex-Token.
    *   `PLEX_CLIENT_IDENTIFIER`: Optional. A unique UUID for this app to identify itself to Plex.tv. If not set, one may be generated.
*   **Application Settings (Required):**
    *   `APP_BASE_URL`: The public root URL where this application is accessible (e.g., `https://pum.yourdomain.com`). This is crucial for generating correct redirect URIs for OAuth and full invite links.
*   **Discord OAuth2 Settings (Optional - for "Login with Discord"):**
    *   `DISCORD_OAUTH_CLIENT_ID`: Your Discord Application's Client ID.
    *   `DISCORD_OAUTH_CLIENT_SECRET`: Your Discord Application's Client Secret.
*   **Discord Bot Settings (Optional - for bot features):**
    *   `DISCORD_BOT_ENABLED`: Set to `true` to enable bot features.
    *   `DISCORD_BOT_TOKEN`: Your Discord Bot's token.
    *   `DISCORD_SERVER_ID`: The ID of your Discord server for membership checks/role monitoring.
    *   `DISCORD_BOT_APP_ID`: Your Discord Application's ID (same as Client ID usually, for slash commands).
    *   `ADMIN_DISCORD_ID`: Your personal Discord User ID for the bot to send you admin DMs.
    *   `DISCORD_COMMAND_CHANNEL_ID`: Channel ID where users can use bot commands (like invite requests).
    *   `DISCORD_PLEX_ACCESS_ROLE_ID`: Role ID that signifies a user has Plex access (for monitoring).
    *   `DISCORD_MENTION_ROLE_ID`: Optional Role ID to mention in bot-created invite threads.
    *   `DISCORD_BOT_USER_WHITELIST`: Comma or newline-separated list of Plex usernames for special bot permissions.

## Flask CLI Commands

(Run these with `flask <command>` after activating your virtual environment)

*   `flask db init` (Run once to initialize migrations folder)
*   `flask db migrate -m "description"` (Generate a new migration after model changes)
*   `flask db upgrade` (Apply pending migrations to the database)
*   `flask create_admin` (Prompts to create a new admin user with username/password)
*   `flask reset_setup_flag` (Resets the `SETUP_COMPLETED` flag, re-enabling the setup wizard)
*   `flask list_settings` (Displays all current application settings from the database)
*   `flask set_setting KEY VALUE` (Sets or updates a specific application setting)
*   `flask register_jobs_cli` (Ensures scheduled jobs are defined in the database - run this before starting Gunicorn)
*   `flask start_services_dev` (For local development: starts scheduler and bot in the foreground)
*   `flask clear_invites [--expired-only]` (Clears invite links)

## Project Structure Overview

The project follows a standard Flask application structure:

*   `PUM/` (Root Directory)
    *   `.env`, `.flaskenv`, `.gitignore`, `config.py` (Configuration)
    *   `Dockerfile`, `docker-compose.yml` (Docker setup)
    *   `requirements.txt` (Python dependencies)
    *   `package.json`, `tailwind.config.js`, `postcss.config.js` (Frontend tooling)
    *   `run.py` (Application entry point for Flask dev server)
    *   `instance/` (Instance-specific files, e.g., SQLite DB, session files - Gitignored)
    *   `migrations/` (Database migration scripts)
    *   `app/` (Main application package)
        *   `__init__.py`: Application factory, initializes extensions, registers blueprints.
        *   `models.py`: SQLAlchemy database models.
        *   `forms.py`: WTForms definitions.
        *   `routes_*.py`: Blueprint route definitions for different sections of the app.
        *   `plex_utils.py`, `discord_utils.py`: Helper functions for Plex and Discord APIs.
        *   `scheduler_tasks.py`: APScheduler background task definitions.
        *   `static/`: Static files (CSS, JS, images).
        *   `templates/`: Jinja2 HTML templates.

## Troubleshooting Scheduler

If scheduled tasks (like Discord checks) are not running:
1.  Ensure `flask register_jobs_cli` was run successfully before starting the main application server (Gunicorn).
2.  Check the application logs (`docker-compose logs -f pum` if using Docker) for messages from "APScheduler". Set `FLASK_DEBUG=1` to get more verbose scheduler logs.
3.  Verify the `apscheduler_jobs` table in your database contains the expected jobs and their `next_run_time` is updating.
4.  Ensure only one Gunicorn worker (or one primary process in dev) is actively running the scheduler jobs to avoid conflicts if using a non-cluster-aware job store setup (SQLAlchemyJobStore is generally good for this).
