FROM kalilinux/kali-rolling

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    wpscan \
    nikto \
    gobuster \
    sqlmap \
    proxychains4 \
    nodejs \
    npm \
    git \
    curl \
    wget \
    iputils-ping \
    # Headless Chrome dependencies for gowitness/puppeteer
    libnss3 libxss1 libasound2 libatk-bridge2.0-0 libgtk-3-0 libgbm1 \
    && rm -rf /var/lib/apt/lists/*

# Install specific tools that might not be in standard apt repos but are needed
# We assume they might be installed globally or via pip in the venv
# Note: Whatweb is in Kali
RUN apt-get update && apt-get install -y whatweb joomscan exploitdb && rm -rf /var/lib/apt/lists/*

# Setup application directory
WORKDIR /app

# Create a virtual environment and install Python dependencies
COPY requirements.txt .
RUN python3 -m venv venv
RUN ./venv/bin/pip install -r requirements.txt
RUN ./venv/bin/pip install droopescan

# Install gowitness (Go binary) if needed, or other external tools.
# Matrix scanner fetches subfinder, nuclei, etc., in `run.sh` but it's better if we have some pre-installed.
RUN apt-get update && apt-get install -y nuclei subfinder sublist3r && rm -rf /var/lib/apt/lists/*

# Copy the rest of the application
COPY . .

# Set environment variables for Flask inside Docker
ENV FLASK_HOST=0.0.0.0
# We are running as root inside Docker, no sudo needed
ENV IN_DOCKER=1

EXPOSE 5000

# Start the Flask app using the virtual environment
CMD ["./venv/bin/python3", "app.py"]
