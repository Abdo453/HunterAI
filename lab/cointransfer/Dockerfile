FROM python:3.11-slim
RUN pip install --no-cache-dir flask pyjwt
COPY coin_transfer_mock.py /app/coin_transfer_mock.py
WORKDIR /app
EXPOSE 5000
CMD ["python", "coin_transfer_mock.py"]