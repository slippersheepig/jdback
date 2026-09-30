FROM python:slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN groupadd -r app && useradd -r -g app app
USER app

EXPOSE 5000

CMD ["python", "app.py"]
