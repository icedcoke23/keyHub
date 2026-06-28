FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 先装依赖（利用缓存层）
COPY pyproject.toml README.md ./
COPY keyhub ./keyhub
RUN pip install --no-cache-dir -e .

# 数据目录
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8000

# 默认启动服务；初始化请用 docker compose run keyhub init
CMD ["keyhub", "serve", "--host", "0.0.0.0", "--port", "8000"]
