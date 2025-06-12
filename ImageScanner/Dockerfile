# --- Step 1: Build Angular frontend ---
FROM node:18 AS frontend-builder

WORKDIR /app
COPY frontend/ ./frontend/
WORKDIR /app/frontend

RUN npm install
RUN npm run build --prod

# --- Step 2: Build Python backend and serve Angular ---
FROM python:3.10-slim

COPY installScript.sh /tmp/installScript.sh
# Install dependencies
# RUN apt-get update && apt-get install -y \
#     curl ca-certificates \
#  && /bin/sh /tmp/installScript.sh -b /usr/local/bin \
#  && rm /tmp/installScript.sh \
#  && apt-get clean
RUN apt-get update && apt-get install -y \
    curl gnupg ca-certificates \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && apt-get clean

# Set work directory
WORKDIR /app

# Copy backend code
COPY app/ ./app/
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy built Angular app
COPY --from=frontend-builder /app/frontend/dist/scanner-frontend ./frontend/dist/scanner-frontend

# Expose API port
EXPOSE 8000

# Run the app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
