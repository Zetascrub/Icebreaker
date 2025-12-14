FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    nmap \
    iputils-ping \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml /app/
COPY README.md /app/
COPY icebreaker /app/icebreaker/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Install Playwright browsers (chromium for screenshots)
RUN playwright install --with-deps chromium

# Create directories for data and set permissions
RUN mkdir -p /app/runs /app/screenshots /data && \
    chmod 777 /data /app/screenshots

# Expose port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Run the application
CMD ["icebreaker-web"]
