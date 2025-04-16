# Use official Python image
FROM python:3.11-slim

# Install required Linux packages
RUN apt-get update && \
    apt-get install -y nmap whois curl iputils-ping && \
    apt-get clean

# Set the working directory
WORKDIR /app

# Copy all project files to container
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask app port
EXPOSE 10000

# Command to run the app
CMD ["python", "app.py"]
