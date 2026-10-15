# Official GitHub Actions runner image, selected 2026-10-14.
FROM ghcr.io/actions/actions-runner@sha256:660f7b9d1e0007274f7c867e220b3c382137ef5a30d8e501a025ad50dbd5fb9d
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-yaml \
    && rm -rf /var/lib/apt/lists/*
USER runner
WORKDIR /home/runner
