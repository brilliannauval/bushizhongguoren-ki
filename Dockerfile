FROM python:3.13-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential make && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY securebox ./securebox
RUN make -C securebox/crypto_asm clean all

FROM python:3.13-slim
ENV APP_ENV=production PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OBJECT_DIR=/tmp/securebox-objects
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home securebox
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /app/securebox ./securebox
COPY --from=build /app/securebox/crypto_asm/libcrypto_asm.so ./securebox/crypto_asm/libcrypto_asm.so
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
COPY scripts/container-start.sh ./scripts/container-start.sh
RUN chmod 0555 scripts/container-start.sh \
    && mkdir -p /tmp/securebox-objects /data/objects \
    && chown -R securebox:securebox /app /tmp/securebox-objects /data
USER securebox
EXPOSE 8000
CMD ["./scripts/container-start.sh"]
