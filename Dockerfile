FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN addgroup -S app && adduser -S app -G app
USER app

EXPOSE 5000

CMD ["python", "app.py"]
