# dd-honeypot-auditor lab image
#
# Layers the 5 lab honeypot configs (SSH, Telnet, MySQL, Redis, PostgreSQL)
# on top of the official DataTrap image, so one `docker build` + one
# `docker run` gives you a fully configured local honeypot to audit.
#
# Lab path: docs/tutorials/dd-honeypot-lab-demo/
# Build:    docker build -t dd-honeypot-lab .
# Run:      docker run -d --name dd-honeypot-lab \
#             -p 127.0.0.1:2222:22 -p 127.0.0.1:23:23 -p 127.0.0.1:3306:3306 \
#             -p 127.0.0.1:6380:6379 -p 127.0.0.1:5433:5432 \
#             dd-honeypot-lab

FROM ghcr.io/thalesgroup/dd-honeypot:latest

# The container scans /data/honeypot at startup: one subfolder per honeypot,
# each with a config.json (see TUTORIAL.md for the schema).
COPY honeypot/ /data/honeypot/

# This lab has no AWS Bedrock credentials, so make the optional LLM fallback
# fail instantly instead of hanging on metadata-service lookups.
# Dataset-matched requests (what the auditor mostly sends) are unaffected.
ENV AWS_EC2_METADATA_DISABLED=true
