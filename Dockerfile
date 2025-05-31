# Dockerfile

# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p instance instance/flask_session

# Set Flask environment variables
# Point FLASK_APP to the script that creates the 'app' instance (run.py)
ENV FLASK_APP=run.py 
ENV FLASK_DEBUG=1

EXPOSE 5000

# Define the command to run the application
# Gunicorn command uses the factory directly: 'app:create_app()'
CMD ["sh", "-c", "flask db upgrade && flask register_jobs_cli && gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 --worker-class gthread --timeout 120 'app:create_app()'"]