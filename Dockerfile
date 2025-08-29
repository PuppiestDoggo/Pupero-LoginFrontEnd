# Flask Frontend - Alpine
FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_RUN_PORT=5000

RUN apk add --no-cache build-base gcc musl-dev linux-headers libffi-dev mariadb-connector-c-dev python3-dev

WORKDIR /app
COPY FlaskProject/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY FlaskProject /app

EXPOSE 5000

CMD ["/bin/sh", "-c", "flask run --host 0.0.0.0 --port ${PORT:-5000}"]
