FROM python:3.12-slim

WORKDIR /app

# Copy agent files
COPY . .

# Make scripts executable
RUN chmod +x entrypoint.sh

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]