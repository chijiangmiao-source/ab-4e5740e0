# Verification image: needs both Node (frontend build check) and Python
# (rule tests + HTTP smoke). The workspace is bind-mounted at run time.
FROM node:20-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["python3", "/workspace/verify/run.py"]
