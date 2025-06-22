# File: Dockerfile

# Stage 1: Python application stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP=run.py
# FLASK_ENV can be set here or via docker-compose.yml environment section
# For production images, you might set ENV FLASK_ENV=production here.
# For development, it's often handled by .flaskenv or docker-compose.

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt .
# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entrypoint script first and make it executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy the rest of the application code
# This includes your pre-built static/css/output.css
COPY . .

# Create a non-root user to run the application
# Using --no-create-home for a simpler system user
RUN addgroup --system appuser && adduser --system --ingroup appuser --no-create-home appuser

# Ensure the instance folder exists and is writable by the appuser
# The volume mount from docker-compose.yml will handle the actual /app/instance persistence.
# This step ensures the directory structure is present if the volume is new or empty.
RUN mkdir -p /app/instance && chown -R appuser:appuser /app/instance

# Switch to the non-root user
USER appuser

# Expose the port the app runs on (Gunicorn will bind to this inside the container)
EXPOSE 5000

# Define the entrypoint to run the script that handles migrations and starts Gunicorn
ENTRYPOINT ["/entrypoint.sh"]

# CMD is no longer needed here as 'exec gunicorn ...' in entrypoint.sh handles the final command.
# If entrypoint.sh was just for migrations and didn't 'exec', you'd keep CMD.