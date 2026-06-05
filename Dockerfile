FROM python:3.11-slim

WORKDIR /app

# Instalam dependentele de sistem necesare pentru chromadb si gitpython
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiem requirements si instalam pachete Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiem codul sursa
COPY . .

# Cream directoarele necesare (vectorstore si memory sunt montate ca volume,
# dar le cream si local ca fallback pentru dezvoltare fara Docker)
RUN mkdir -p logs data/repos memory vectorstore

# Port-ul Streamlit
EXPOSE 8501

# Cheile API vin prin --env-file .env la docker compose up — nu hardcodate
CMD ["streamlit", "run", "src/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
