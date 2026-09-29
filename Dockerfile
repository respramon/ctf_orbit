FROM python:3.12-slim

ARG EXTRAS=full
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/ctf-orbit
COPY . .
RUN if [ -n "$EXTRAS" ]; then python -m pip install --no-cache-dir ".[${EXTRAS}]"; else python -m pip install --no-cache-dir .; fi
RUN mkdir -p /work && chmod 1777 /work
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["ctf-orbit"]
CMD ["--help"]

