# bbht toolkit -- Linux container with the scripts, recon tools, and the
# web dashboard (webui/) that gives real-time job status in a browser.
#
# Build (from repo root):
#   docker build -f docker/Dockerfile -t bbht:latest .
#
# Run (see docker-compose.yml for the easier path):
#   docker run -p 8080:8080 -e API_TOKEN=change-me -v bbht-data:/data bbht:latest

FROM golang:1.23-bookworm AS tools

# Build the Go-based recon tools once, in a separate stage, so the final
# image doesn't need the full Go toolchain.
#
# Each tool is installed independently with its own RUN line: if one
# tool's latest release bumps its minimum Go version, changes its module
# path, or has a transient fetch failure, that failure is isolated and
# logged instead of aborting the whole build (the old single chained
# `&&` RUN meant ANY one failure killed every tool, including ones that
# would have succeeded, and hid which one actually failed behind a bare
# "exit code: 1"). Missing tools are reported by setup.sh/quickwin_scan.sh
# at runtime -- the toolkit already degrades gracefully without them.
RUN set -x; \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "WARN: subfinder install failed"; \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest || echo "WARN: httpx install failed"; \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || echo "WARN: dnsx install failed"; \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "WARN: nuclei install failed"; \
    go install github.com/lc/gau/v2/cmd/gau@latest || echo "WARN: gau install failed"; \
    go install github.com/PentestPad/subzy@latest || echo "WARN: subzy install failed"; \
    ls -la /go/bin/ || echo "WARN: no tools installed at all"

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv curl ca-certificates dnsutils git \
    && rm -rf /var/lib/apt/lists/*

# Pull the prebuilt Go recon tools from the builder stage. Trailing
# slashes (copy directory CONTENTS) rather than a /* glob, so this
# still succeeds even if the builder stage installed zero tools (a
# glob with no matches fails the build outright; a directory copy of
# an empty directory does not).
COPY --from=tools /go/bin/ /usr/local/bin/

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
