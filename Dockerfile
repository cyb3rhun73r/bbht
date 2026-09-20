# Bug Hunt HQ - web app image
#
# Builds the same recon/triage engine as the desktop GUI (bughunthq/bughunthq.py)
# behind a small FastAPI web front end (bughunthq/web/app.py), with the
# recon toolset (sqlmap, nuclei, ffuf, dalfox, wpscan, ...) vendored in.
#
# Authorized security testing only - see bughunthq/README.md.

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-tk \
        curl \
        git \
        jq \
        build-essential \
        libcurl4-openssl-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        ruby-full \
        ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# wpscan: not vendored by fetch_tools.py (needs a Ruby runtime), so install
# it as a gem instead.
RUN gem install wpscan --no-document

WORKDIR /app
COPY bughunthq/requirements.txt bughunthq/requirements.txt
COPY bughunthq/web/requirements.txt bughunthq/web/requirements.txt
RUN pip install --no-cache-dir -r bughunthq/requirements.txt -r bughunthq/web/requirements.txt

COPY . .

# Vendor the recon toolset (nuclei, subfinder, ffuf, dalfox, tlsx, trivy,
# sqlmap, git-dumper, commix, jwt_tool, corsy) at build time so the image is
# self-contained - no network fetch needed at runtime just to get tools.
RUN python bughunthq/tools/fetch_tools.py || true

EXPOSE 8000

CMD ["uvicorn", "bughunthq.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
