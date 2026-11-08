# ============================================================================
# BaitBox — M6 Egress Filter Dockerfile (mitmproxy + custom containment rules)
# ============================================================================
FROM mitmproxy/mitmproxy:10.4.2

WORKDIR /app
COPY filter_addon.py /app/filter_addon.py

EXPOSE 8080

ENTRYPOINT ["mitmdump", "-s", "/app/filter_addon.py", "--listen-host", "0.0.0.0", "--listen-port", "8080", "--set", "block_global=false"]
