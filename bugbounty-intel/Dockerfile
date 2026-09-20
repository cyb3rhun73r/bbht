FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
COPY config.yaml scope.example.yaml ./

RUN pip install --no-cache-dir -e .

ENV BBINTEL_DB=/root/.bugbounty-intel/data.sqlite3
VOLUME ["/root/.bugbounty-intel"]

ENTRYPOINT ["bugbounty-intel"]
CMD ["--help"]
