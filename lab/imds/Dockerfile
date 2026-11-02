FROM python:3.11-slim
RUN pip install --no-cache-dir flask
COPY imds.py /app/imds.py
WORKDIR /app
EXPOSE 80
CMD ["python", "imds.py"]
