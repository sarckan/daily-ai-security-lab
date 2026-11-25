# Build stage
FROM python:3.12-slim AS build
WORKDIR /src
COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

# Runtime stage
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && useradd --uid 10001 app
COPY --chown=app:app . /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
ENTRYPOINT ["tini", "--"]
CMD ["python", "/app/app.py"]
