FROM python:3.11-slim
RUN pip install --no-cache-dir flask requests
COPY spring_mock.py /app/spring_mock.py
WORKDIR /app
EXPOSE 5000
CMD ["python", "spring_mock.py"]
