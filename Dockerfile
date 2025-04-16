# Use official Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# System dependencies (whois + nmap)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        whois \
        nmap \
        curl \
        gcc \
        libffi-dev \
        libssl-dev \
        && rm -rf /var/lib/apt/lists/*

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . .

# Expose port (optional, based on your setup)
EXPOSE 10000

# Start the Flask app
CMD ["python", "app.py"]
