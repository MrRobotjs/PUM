# Plex User Manager (PUM)

[![Docker Image CI](https://github.com/MrRobotjs/PUM/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/MrRobotjs/PUM/actions/workflows/docker-publish.yml)
[![GitHub stars](https://img.shields.io/github/stars/MrRobotjs/PUM.svg?style=social&label=Star&maxAge=2592000)](https://github.com/MrRobotjs/PUM/stargazers/)
[![](https://dcbadge.limes.pink/api/server/https://discord.gg/QGHQWpGNgX)](https://discord.gg/QGHQWpGNgX)
[![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.com/donate/?business=D7BJAJ9ZY4GRC&no_recurring=0&currency_code=USD)


Plex User Manager (PUM) is a web application designed to simplify and enhance the management of users on your Plex Media Server. It provides a user-friendly interface for administrators to handle user invitations, track activity, manage library access, and automate certain user lifecycle tasks.

Dashboard             |  Invites
:-------------------------:|:-------------------------:
![image](https://github.com/user-attachments/assets/18db06e2-66c2-4e15-a010-59dc5499761d)  |  ![image](https://github.com/user-attachments/assets/dcb72d92-94f1-4246-aa81-e6163e3ff763)
Users             |  Streaming
![image](https://github.com/user-attachments/assets/77c35536-62fd-44e3-9356-5cd6156fcf26)  |  ![image](https://github.com/user-attachments/assets/755f6dec-c839-4145-9d08-67c2de91303d)

## Features

*   **User Management:**
    *   View all Plex users connected to your server (friends and Plex Home users).
    *   Manually sync users from your Plex server to the PUM database.
    *   Edit user details, including notes and library access.
    *   Remove users from PUM and revoke their access from the Plex server.
    *   Mass edit capabilities: update libraries or delete multiple users at once.
*   **Invite System:**
    *   Create flexible invite links (unique tokens or custom paths).
    *   Set expiration dates for invite links.
    *   Limit the number of times an invite link can be used.
    *   Specify which Plex libraries are granted upon invite acceptance.
    *   Toggle whether invited users can download/sync content.
    *   **Membership Duration:** Set a specific duration (in days) for how long a user has access after accepting an invite. Expired users are automatically removed by a scheduled task.
    *   View invite usage history.
*   **Discord Integration (Optional):**
    *   **OAuth Linking:** Allow users to link their Discord account when accepting an invite. Admin can also link their own Discord account.
    *   **Mandatory/Optional SSO:** Configure whether Discord linking is required or optional on the invite page.
    *   *(Future Bot Features: The groundwork is laid for more advanced bot interactions like role-based invites or auto-removal based on Discord server activity. Currently, the bot core is included but advanced features are pending.)*
*   **Dashboard & Monitoring:**
    *   At-a-glance dashboard with key statistics (total users, active invites, active streams).
    *   Plex server status indicator (online/offline, version).
    *   **Active Streams:** View currently active Plex streams with details like user, player, media, progress, quality, and transcode information (similar to Tautulli).
    *   Detailed event history/log for all significant application and admin actions.
*   **User Lifecycle Management:**
    *   **Purge Inactive Users:** Preview and purge users who haven't streamed content for a configurable period.
    *   Exclude Plex Home users, users who share back, and whitelisted users from purges.
    *   Automated removal of users whose invite-based membership has expired.
*   **Admin & Security:**
    *   Secure admin login via local username/password or Plex SSO.
    *   Multi-step setup wizard for initial configuration.
    *   CSRF protection.
*   **Modern UI:**
    *   Clean, responsive user interface built with Flask, Tailwind CSS, and DaisyUI.
    *   Interactive elements powered by HTMX for a smoother experience.
    *   Light and Dark theme support.

## Docker Deployment

The easiest way to deploy Plex User Manager is using Docker.

### Using Docker Compose

1.  **Create a `docker-compose.yml` file:**
    ```yaml

    services:
      pum:
        image: ghcr.io/mrrobotjs/pum:latest # Or use a specific version tag, e.g., ghcr.io/mrrobotjs/pum:v0.1.0
        container_name: pum # Or your preferred container name
        restart: unless-stopped
        ports:
          - "5699:5000" # <host_port>:<container_port> (Gunicorn runs on 5000 inside)
        volumes:
          # This directory on your host will store PUM's persistent data (database, etc.)
          - ./plexusermanager:/app/instance 
        environment:
          - TZ=America/New_York # REQUIRED: Set your local timezone (see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)
          - FLASK_LOG_LEVEL=INFO # Optional: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default is INFO.
          # - PUID=1000 # Optional: User ID for the application process inside the container
          # - PGID=1000 # Optional: Group ID for the application process inside the container
        #depends_on:
          #plex: # Optional: if you run Plex in Docker and want PUM to start after Plex
            #condition: service_healthy # Or service_started
    
    # Optional: Example Plex service definition if running Plex via Docker Compose too
    #   plex:
    #     image: lscr.io/linuxserver/plex:latest
    #     container_name: plex
    #     network_mode: host # Or configure ports specifically
    #     environment:
    #       - PUID=1000
    #       - PGID=1000
    #       - TZ=America/New_York
    #       - VERSION=docker
    #       - PLEX_CLAIM=YOUR_PLEX_CLAIM_TOKEN # For initial setup
    #     volumes:
    #       - ./plex_config:/config
    #       - /path/to/your/tvshows:/data/tvshows
    #       - /path/to/your/movies:/data/movies
    #     restart: unless-stopped
    #     healthcheck: # Optional healthcheck for depends_on
    #       test: ["CMD", "curl", "-f", "http://localhost:32400/identity"]
    #       interval: 30s
    #       timeout: 10s
    #       retries: 5

    ```

2.  **Prepare Host Directory:**
    Create the directory on your host machine that you specified in the `volumes` section for PUM. For example:
    ```bash
    mkdir ./plexusermanager_data
    ```
    This directory will store `pum.db` (the application database) and other instance-specific files.

3.  **Customize `docker-compose.yml`:**
    *   **Image Tag:** Change `ghcr.io/mrrobotjs/pum:latest` to a specific version tag (e.g., `ghcr.io/mrrobotjs/pum:v0.1.0`) if desired. Find available tags on the [Packages page](https://github.com/MrRobotjs/PUM/pkgs/container/pum) of the repository.
    *   **Port Mapping:** Adjust the host port (`5699` in `- "5699:5000"`) if it's already in use on your system.
    *   **Volume Path:** Ensure the host path in the `volumes` section (e.g., `./plexusermanager_data`) points to the directory you created.
    *   **Timezone (`TZ`):** **Crucial!** Set this to your local timezone from the [tz database list](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) (e.g., `Europe/London`, `America/Los_Angeles`). This is important for correct display of timestamps and for scheduled tasks.
    *   **`PUID` and `PGID` (Optional):** If you need the application process inside the container to run as a specific user/group on your host system (relevant for file permissions on mounted volumes if you were mounting media config directly, less so for just the instance folder which Docker typically handles), you can set these. Find your user's ID with `id -u` and group ID with `id -g` on Linux.

4.  **Run the Application:**
    Navigate to the directory containing your `docker-compose.yml` file and run:
    ```bash
    docker-compose up -d
    ```
    (Or `docker compose up -d` if you are using Docker Compose V2 CLI).

5.  **Initial Setup:**
    *   Access PUM in your browser at `http://<your_host_ip_or_domain>:<host_port>` (e.g., `http://localhost:5699`).
    *   You will be guided through a one-time setup wizard to create an admin account, configure your Plex server connection, and set the application's base URL.

### Available Docker Image Tags

*   `latest`: The latest stable build, usually from the `main` branch.
*   `vX.Y.Z` (e.g., `v0.1.0`): Specific release versions. It's recommended to use these versioned tags for stability in production.

You can find all available image tags on the [GitHub Packages page for PUM](https://github.com/MrRobotjs/PUM/pkgs/container/pum).

## Configuration

Most application settings are configurable through the web UI after initial setup. Key settings include:

*   **General:** Application Name.
*   **Plex:** Plex Server URL, Plex Token, Session Monitoring Interval.
*   **Discord:** OAuth credentials, Bot Token, Server/Channel IDs, and behavior toggles.
*   **Advanced:** Secret Key regeneration.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue.
