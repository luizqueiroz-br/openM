FROM python:3.11-slim

WORKDIR /app

# gcc + libpq-dev: build-time deps for psycopg2-binary.
# (postgresql-client removido no issue #36 — não há mais psql no
# entrypoint.sh, agora é Flask-Migrate / Alembic.)
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
