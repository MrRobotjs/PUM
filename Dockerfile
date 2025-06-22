# File: Dockerfile (Manual CSS Build)

# Stage 1: Python application stage (No longer a multi-stage build for frontend)
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP=run.py

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (if any) - usually not needed for slim if Python packages are pure Python
# RUN apt-get update && apt-get install -y --no-install-recommends gcc build-essential && rm -rf /var/lib/apt/lists/*

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application code (including your manually built static/css/output.css)
COPY . .
# Ensure app/static/css/output.css is present in your project directory *before* building the image.

# Create a non-root user to run the application
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser

# Ensure the instance folder is writable by the appuser
# The instance folder will be created by Flask if it doesn't exist, but ensure permissions
# The volume mount from docker-compose.yml will handle the actual /app/instance persistence
RUN mkdir -p /app/instance && chown -R appuser:appuser /app/instance
USER appuser

# Expose the port the app runs on
EXPOSE 5000

# Define the command to run the application using Gunicorn
# The bind address 0.0.0.0 makes it accessible from outside the container (on the mapped port)
# `run:app` refers to the Flask app instance `app` in `run.py`
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--forwarded-allow-ips", "*", "run:app"]