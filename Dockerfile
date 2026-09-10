FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies (build-essential for native Python packages, curl for HEALTHCHECK)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies (separate COPY for better Docker build caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create required data directories and set permissions
RUN mkdir -p /app/raw /app/integrity /app/data && chmod -R 777 /app/raw /app/integrity /app/data

# Expose the API/Dashboard port and UDP Syslog listener port
EXPOSE 8000
EXPOSE 5514/udp

# Healthcheck — hosting platforms and orchestrators use this to verify the container is alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the FastAPI server using Uvicorn (no --reload in production)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
