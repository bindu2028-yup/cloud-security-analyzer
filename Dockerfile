
# Stage 1: Install Python dependencies
FROM python:3.11-slim AS builder

WORKDIR /install

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install/packages -r requirements.txt \
    && pip install --no-cache-dir --prefix=/install/packages --upgrade "setuptools==84.0.0" "wheel>=0.46.2"

# Stage 2: Create the final application image
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade "setuptools==84.0.0" "wheel>=0.46.2"

COPY --from=builder /install/packages /usr/local

COPY app.py .
COPY security_logs.csv .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
