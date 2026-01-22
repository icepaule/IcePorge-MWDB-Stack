FROM python:3.11-slim

LABEL maintainer="CAPE Analysis Pipeline"
LABEL description="Karton module for submitting samples to CAPEv2"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY cape_submitter.py .

# Run as non-root user
RUN useradd -m -u 1000 karton
USER karton

# Default command
CMD ["python", "cape_submitter.py"]
