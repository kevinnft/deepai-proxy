FROM python:3.12-slim
WORKDIR /app
COPY server.py run.sh ./
RUN chmod +x /app/server.py /app/run.sh
ENV HOST=0.0.0.0 PORT=1417 CONFIG_DIR=/data
VOLUME ["/data"]
EXPOSE 1417
CMD ["python3", "/app/server.py"]
