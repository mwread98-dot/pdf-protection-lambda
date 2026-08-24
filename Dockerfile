FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        qpdf \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/task

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    --requirement requirements.txt

COPY app.py .

RUN python -m py_compile /var/task/app.py

RUN qpdf --version

ENTRYPOINT ["/usr/local/bin/python", "-m", "awslambdaric"]

CMD ["app.lambda_handler"]
