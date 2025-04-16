# Use an official Python image
FROM python:3.11-slim

# Install system dependencies including nmap
RUN apt-get update && \
    apt-get install -y nmap whois && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose the port the app runs on
EXPOSE 10000

# Start the Flask app
CMD ["python", "app.py"]
