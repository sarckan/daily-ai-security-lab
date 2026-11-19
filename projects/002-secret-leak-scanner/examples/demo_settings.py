# Deliberately leaky demo config. Every value here is FAKE and only exists
# so you can see what the scanner reports. Never commit real secrets.

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented sample key id
DATABASE_URL = "postgres://admin:S3cr3tPass@db.internal:5432/app"
SESSION_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vLXVzZXIifQ.c2lnbmF0dXJlLWRlbW8"
PAYMENT_API_KEY = "q8Zt3LmX4vR9pN2wK7bY5cH1"

DEBUG_PASSWORD = "changeme123"  # placeholder -> ignored
TEST_SECRET = "Xk29fLq0Pz8wVb3n"  # secret-scan: ignore  (reviewed test fixture)
TIMEOUT_SECONDS = 30
