# bbht toolkit -- Linux container with the scripts, recon tools, and the
# web dashboard (webui/) that gives real-time job status in a browser.
#
# Build (from repo root):
#   docker build -f docker/Dockerfile -t bbht:latest .
#
# Run (see docker-compose.yml for the easier path):
#   docker run -p 8080:8080 -e API_TOKEN=change-me -v bbht-data:/data bbht:latest

FROM golang:1.22-bookworm AS tools

# Build the Go-based recon tools once, in a separate stage, so the final
# image doesn't need the full Go toolchain.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/PentestPad/subzy@latest

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv curl ca-certificates dnsutils git \
    && rm -rf /var/lib/apt/lists/*

# Pull the prebuilt Go recon tools from the builder stage.
COPY --from=tools /go/bin/* /usr/local/bin/

WORKDIR /app
COPY scripts/ ./scripts/
COPY .claude/ ./.claude/
COPY webui/ ./webui/
COPY docker/entrypoint.sh ./docker/entrypoint.sh
COPY README.md ./README.md

RUN pip3 install --no-cache-dir --break-system-packages -r webui/requirements.txt \
 && chmod +x scripts/*.sh scripts/*.py docker/entrypoint.sh

# Personal tracking data (programs.csv, findings.csv, quickwin_results/,
# dashboard_audit.log) lives in a volume so it survives container
# restarts/rebuilds without polluting the image.
VOLUME ["/app/scripts_data"]
ENV TRACKER_DATA_DIR=/app/scripts_data

EXPOSE 8080

ENTRYPOINT ["/app/docker/entrypoint.sh"]
