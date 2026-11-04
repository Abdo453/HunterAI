# CTF Lab app server — deliberately vulnerable mirrored Flask app.
# Host-side isolation is enforced by the compose port mapping (127.0.0.1),
# not by this binding: inside the container the app must listen on all
# interfaces so Docker's NAT can reach it.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app_server.py .
EXPOSE 5354
CMD ["python", "app_server.py"]
