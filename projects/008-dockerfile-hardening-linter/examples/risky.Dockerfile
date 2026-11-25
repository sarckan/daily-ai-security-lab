FROM python:latest
ENV DB_PASSWORD=changeme
RUN apt-get update && apt-get install -y curl git
RUN curl -fsSL https://example.com/install.sh | bash
RUN pip install --trusted-host pypi.org -r requirements.txt
ADD https://example.com/tool.tar.gz /opt/
RUN chmod -R 777 /app
EXPOSE 22 8000
CMD ["python", "app.py"]
