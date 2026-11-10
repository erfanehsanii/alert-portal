FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system app && \
    useradd --system --gid app --home-dir /app app

COPY requirements.txt /app/requirements.txt

RUN pip install \
    --no-cache-dir \
    --index-url https://pypi.org/simple \
    -r /app/requirements.txt

COPY --chown=app:app app/ /app/app/

USER app:app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
