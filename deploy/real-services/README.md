# Real-services baseline lab

Production-like Docker faces for **false-positive** checks. Expect
**Likely Real Host** / score ≈ 0 — not a honeypot.

```bash
docker compose -f deploy/docker-compose.real-services.yml up -d --build
./scripts/real-services-lab.sh
```

Binds `127.0.0.1` only. Remaps ports that collide with other local stacks
(Redis/Postgres/SSH/FTP). Includes nginx, Redis, Postgres, MySQL, Memcached,
Elasticsearch, Mosquitto, CoreDNS, chrony, MongoDB, OpenSSH (SFTP), Squid,
Samba, vsftpd, telnetd, tftpd-hpa, Dovecot POP3, and Postfix.

**TFTP:** replies use an ephemeral TID. Docker Desktop NAT drops host→published
UDP TID replies, so the lab script probes TFTP from inside the compose network.

Configs and Dockerfiles live under `deploy/real-services/`.
