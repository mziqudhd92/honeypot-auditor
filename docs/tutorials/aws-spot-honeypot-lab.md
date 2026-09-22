# Beginner tutorial: audit three honeypots on an AWS Spot instance

This walkthrough deploys **Cowrie**, **Dionaea**, and **OpenCanary** (the
popular multi-service “dd-style” decoy) on one cheap AWS Spot VM, binds them to
**localhost only**, then runs **honeypot-auditor** against each stack so you can
see Confirmed Honeypot results without exposing decoys to the internet.

**Time:** about 30–45 minutes  
**Cost:** typically under $0.05/hour for a `t3.medium` Spot in `us-east-1`  
**Skill level:** beginner-friendly if you already have an AWS account and can
run terminal commands

> **Safety.** Only probe hosts and ports you own or have written permission to
> test. In this lab everything listens on `127.0.0.1`, and the auditor runs
> *on the same machine*. Do not publish honeypot ports to `0.0.0.0` unless you
> know what you are doing.

---

## What you will build

```
┌─────────────────────────────────────────────────────────┐
│  AWS Spot (Ubuntu)  ·  SSM Session Manager              │
│                                                         │
│  Docker                                                 │
│   ├─ Cowrie      127.0.0.1:2222 (SSH), :2223 (Telnet) │
│   ├─ Dionaea     2121 FTP · 8081 HTTP · 1445 SMB · …  │
│   └─ OpenCanary  3222 SSH · 8080 HTTP · 3306 MySQL · …│
│                                                         │
│  honeypot-auditor  →  JSON reports under /opt/hpa-lab   │
└─────────────────────────────────────────────────────────┘
```

| Honeypot | Role | Host ports (localhost) |
|----------|------|------------------------|
| **Cowrie** | Medium-interaction SSH/Telnet lure | `2222`, `2223` |
| **Dionaea** | Multi-protocol malware catcher | `2121`, `8081`, `1445`, `5060`, `5900`, `26379`, `13306`, `11433` |
| **OpenCanary** | Lightweight multi-service canary (“dd honeypot” style) | `3222`, `8080`, `3306`, `2122`, `6379` |

---

## Prerequisites

1. An AWS account with permission to create EC2 instances, security groups, and
   IAM roles.
2. AWS CLI v2 installed and configured (`aws sts get-caller-identity` works).
3. Region: this tutorial uses **`us-east-1`** (change if you prefer).
4. Optional but recommended: **Session Manager plugin** so you can shell in
   without managing SSH keys.

```bash
aws sts get-caller-identity
export AWS_DEFAULT_REGION=us-east-1
```

---

## Step 1 — Create an IAM role for SSM

The instance needs the managed policy so you can run commands without opening
SSH to the world.

```bash
# Trust policy: allow EC2 to assume the role
cat > /tmp/hpa-ssm-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
  --role-name honeypot-auditor-lab-ssm \
  --assume-role-policy-document file:///tmp/hpa-ssm-trust.json

aws iam attach-role-policy \
  --role-name honeypot-auditor-lab-ssm \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

aws iam create-instance-profile \
  --instance-profile-name honeypot-auditor-lab-ssm

aws iam add-role-to-instance-profile \
  --instance-profile-name honeypot-auditor-lab-ssm \
  --role-name honeypot-auditor-lab-ssm

# IAM propagation can take ~10–20 seconds
sleep 15
```

Skip role creation if `honeypot-auditor-lab-ssm` already exists.

---

## Step 2 — Security group (SSH optional, SSM preferred)

Honeypots stay on localhost, so you only need outbound HTTPS for Docker pulls
and (optionally) inbound SSH from *your* IP for debugging.

```bash
MY_IP=$(curl -s https://checkip.amazonaws.com)/32
VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)

SG_ID=$(aws ec2 create-security-group \
  --group-name honeypot-auditor-lab-sg \
  --description "HPA Spot lab - admin SSH only" \
  --vpc-id "$VPC_ID" \
  --query GroupId --output text)

aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP"

echo "SG_ID=$SG_ID"
```

---

## Step 3 — Launch a Spot Ubuntu instance

Use a current Ubuntu 24.04 AMI for your region, `t3.medium`, and attach the SSM
instance profile.

```bash
AMI=$(aws ec2 describe-images --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
            "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

# Spot launch specification
cat > /tmp/hpa-spot-spec.json <<EOF
{
  "ImageId": "$AMI",
  "InstanceType": "t3.medium",
  "SecurityGroupIds": ["$SG_ID"],
  "IamInstanceProfile": { "Name": "honeypot-auditor-lab-ssm" },
  "UserData": "$(echo '#!/bin/bash
apt-get update -y
apt-get install -y docker.io docker-compose-v2 python3-venv xxd
systemctl enable --now docker
usermod -aG docker ubuntu
' | base64 | tr -d '\n')"
}
EOF

SPOT_REQ=$(aws ec2 request-spot-instances \
  --instance-count 1 \
  --type one-time \
  --launch-specification file:///tmp/hpa-spot-spec.json \
  --query 'SpotInstanceRequests[0].SpotInstanceRequestId' --output text)

echo "SPOT_REQ=$SPOT_REQ"

# Wait until fulfilled
aws ec2 wait spot-instance-request-fulfilled --spot-instance-request-ids "$SPOT_REQ"
IID=$(aws ec2 describe-spot-instance-requests \
  --spot-instance-request-ids "$SPOT_REQ" \
  --query 'SpotInstanceRequests[0].InstanceId' --output text)
echo "IID=$IID"

aws ec2 create-tags --resources "$IID" \
  --tags Key=Name,Value=honeypot-auditor-lab Key=Purpose,Value=authorized-lab

# Wait for SSM agent (usually 1–3 minutes after boot)
for i in $(seq 1 40); do
  ST=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=$IID" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
  echo "SSM poll $i: $ST"
  [[ "$ST" == "Online" ]] && break
  sleep 10
done
```

---

## Step 4 — Deploy the three honeypots with Docker Compose

Copy the lab files onto the instance with SSM (no SSH key required).

```bash
# Create lab directory + compose on the instance
aws ssm send-command \
  --instance-ids "$IID" \
  --document-name AWS-RunShellScript \
  --timeout-seconds 900 \
  --parameters commands='[
    "mkdir -p /opt/hpa-lab && cd /opt/hpa-lab",
    "cat > opencanary.conf <<'\''EOF'\''\n{\"device.node_id\":\"hpa-opencanary\",\"logger\":{\"class\":\"PyLogger\",\"kwargs\":{\"handlers\":{\"console\":{\"class\":\"logging.StreamHandler\",\"stream\":\"ext://sys.stdout\"}}}},\"portscan.enabled\":false,\"ssh.enabled\":true,\"ssh.port\":2222,\"http.enabled\":true,\"http.port\":80,\"http.banner\":\"Apache/2.4.49 (Ubuntu)\",\"mysql.enabled\":true,\"mysql.port\":3306,\"ftp.enabled\":true,\"ftp.port\":21,\"redis.enabled\":true,\"redis.port\":6379,\"telnet.enabled\":false,\"smb.enabled\":false,\"git.enabled\":false,\"tcpbanner.enabled\":false}\nEOF",
    "cat > docker-compose.yml <<'\''EOF'\''\nname: hpa-lab\nservices:\n  cowrie:\n    image: cowrie/cowrie:latest\n    container_name: hpa-cowrie\n    ports:\n      - \"127.0.0.1:2222:2222/tcp\"\n      - \"127.0.0.1:2223:2223/tcp\"\n    restart: unless-stopped\n  dionaea:\n    image: dinotools/dionaea:latest\n    container_name: hpa-dionaea\n    ports:\n      - \"127.0.0.1:2121:21/tcp\"\n      - \"127.0.0.1:8081:80/tcp\"\n      - \"127.0.0.1:1445:445/tcp\"\n      - \"127.0.0.1:5060:5060/tcp\"\n      - \"127.0.0.1:5900:5900/tcp\"\n      - \"127.0.0.1:26379:6379/tcp\"\n      - \"127.0.0.1:13306:3306/tcp\"\n      - \"127.0.0.1:11433:1433/tcp\"\n    restart: unless-stopped\n  opencanary:\n    image: python:3.11-slim-bookworm\n    container_name: hpa-opencanary\n    volumes:\n      - ./opencanary.conf:/root/.opencanary.conf:ro\n    ports:\n      - \"127.0.0.1:3222:2222/tcp\"\n      - \"127.0.0.1:8080:80/tcp\"\n      - \"127.0.0.1:3306:3306/tcp\"\n      - \"127.0.0.1:2122:21/tcp\"\n      - \"127.0.0.1:6379:6379/tcp\"\n    command: bash -lc \"pip install -q opencanary && opencanaryd --start --uid=nobody && sleep infinity\"\n    restart: unless-stopped\nEOF",
    "cd /opt/hpa-lab && docker compose up -d",
    "docker ps --format \"table {{.Names}}\t{{.Status}}\t{{.Ports}}\""
  ]'
```

Tip: for long scripts, base64-encode a local file and decode on the instance
(avoids shell-escaping pain):

```bash
B64=$(base64 < your-bootstrap.sh | tr -d '\n')
aws ssm send-command --instance-ids "$IID" \
  --document-name AWS-RunShellScript \
  --parameters commands=["echo $B64 | base64 -d > /tmp/bootstrap.sh","chmod +x /tmp/bootstrap.sh","sudo bash /tmp/bootstrap.sh"]
```

Wait until ports answer on localhost:

```bash
aws ssm start-session --target "$IID"
# then inside the instance:
ss -lnt | grep -E '2222|2121|3222'
```

---

## Step 5 — Install honeypot-auditor

On the instance (via SSM session or `send-command`):

```bash
python3 -m venv /opt/hpa-lab/venv
/opt/hpa-lab/venv/bin/pip install -U pip wheel

# Prefer a release when published:
# /opt/hpa-lab/venv/bin/pip install 'honeypot-auditor[full]==1.0.0'

# Or install from GitHub (works today):
/opt/hpa-lab/venv/bin/pip install \
  'honeypot-auditor[full] @ git+https://github.com/mziqudhd92/honeypot-auditor.git@dev'

/opt/hpa-lab/venv/bin/honeypot-auditor --version
```

---

## Step 6 — Run three isolated audits

Use **`-p`** so each scan only touches that honeypot’s ports. Without `-p`, the
default preset may also probe other local listeners (for example Cowrie on
`2222` while you meant to audit only Dionaea).

```bash
HPA=/opt/hpa-lab/venv/bin/honeypot-auditor
mkdir -p /opt/hpa-lab/reports

# 1) Cowrie
$HPA --target 127.0.0.1 -p 2222,2223 \
  --ports ssh=2222,telnet=2223 \
  --timeout 8 -v --output /opt/hpa-lab/reports/cowrie.json

# 2) Dionaea
$HPA --target 127.0.0.1 -p 2121,8081,1445,5060,5900,26379,13306,11433 \
  --ports ftp=2121,http=8081,smb=1445,sip=5060,vnc=5900,redis=26379,mysql=13306,mssql=11433 \
  --timeout 8 -v --output /opt/hpa-lab/reports/dionaea.json

# 3) OpenCanary
$HPA --target 127.0.0.1 -p 3222,8080,3306,2122,6379 \
  --ports ssh=3222,http=8080,mysql=3306,ftp=2122,redis=6379 \
  --timeout 8 -v --output /opt/hpa-lab/reports/opencanary.json
```

Quick scoreboard:

```bash
python3 - <<'PY'
import json, pathlib
root = pathlib.Path('/opt/hpa-lab/reports')
for name in ('cowrie', 'dionaea', 'opencanary'):
    r = json.loads((root / f'{name}.json').read_text())
    hits = [i for i in r['indicators'] if i.get('triggered') and not i.get('suppressed')]
    print(f"{name:12} score={r['score']:5}  {r['threat_level']:20}  hits={len(hits)}")
    for h in hits:
        print(f"  - {h['id']}: {(h.get('detail') or '')[:90]}")
PY
```

---

## Step 7 — Read the results (what “good” looks like)

Reference run from this lab (honeypot-auditor **1.0.0**, Spot `t3.medium`,
`us-east-1`, localhost-only):

| Target | Honeyscore | Threat level | Notable tells |
|--------|------------|--------------|---------------|
| Cowrie | **100** | Confirmed Honeypot | High-fidelity `ssh.kex_facade` (Twisted/Cowrie KEX), arbitrary auth, lure shell |
| Dionaea | **70** | Confirmed Honeypot | Synology-style FTP banner + Docker PASV leak, SMB dialect fail, protocol buffet |
| OpenCanary | **82.5** | Confirmed Honeypot | EOL OpenSSH/MySQL banners, FTP auth lure, 4-protocol buffet |

Machine-readable compact summaries for that run live next to this tutorial:

- [`aws-spot-honeypot-lab-results-summary.json`](./aws-spot-honeypot-lab-results-summary.json)
- [`aws-spot-honeypot-lab-cowrie.json`](./aws-spot-honeypot-lab-cowrie.json)
- [`aws-spot-honeypot-lab-dionaea.json`](./aws-spot-honeypot-lab-dionaea.json)
- [`aws-spot-honeypot-lab-opencanary.json`](./aws-spot-honeypot-lab-opencanary.json)

### How to interpret scores

- **Confirmed Honeypot** means the tool found enough honeypot-like behavior that
  the score crossed the confirmation threshold (see `docs/SCORING.md`).
- A **high-fidelity** hit such as `ssh.kex_facade` is a strong Cowrie tell and
  usually pushes the score near 100.
- Multi-service stacks often trip **`corroboration.protocol_buffet`**: several
  weak/medium lures on one host reinforce each other.

---

## Step 8 — Tear down (stop paying for Spot)

When you are done:

```bash
aws ec2 terminate-instances --instance-ids "$IID"
aws ec2 delete-security-group --group-id "$SG_ID"   # after instance is terminated
# Optional: detach/delete the IAM role + instance profile if you will not reuse them
```

Confirm:

```bash
aws ec2 describe-instances --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].State.Name'
# → shutting-down / terminated
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| SSM never `Online` | Wait for cloud-init; confirm instance profile attached; check outbound HTTPS. |
| OpenCanary ports closed | Image may still be `pip install`ing; `docker logs hpa-opencanary` and wait. |
| Dionaea audit also shows Cowrie hits | You forgot `-p`; default preset still probes SSH `2222`. |
| `honeypot-auditor` not on PyPI | Install from GitHub `@dev` or `@main` as in Step 5. |
| Permission denied on Docker | `sudo usermod -aG docker ubuntu` then new session, or use `sudo docker`. |

---

## Next steps

- Read [`docs/SCORING.md`](../SCORING.md) for how Honeyscore is computed.
- Try `--preset deception-audit` against a *real* service stack and compare scores.
- Record a terminal demo with the scripts under `docs/demo/`.

---

## Lab snapshot (reference)

| Field | Value |
|-------|--------|
| Region | `us-east-1a` |
| Instance | Spot `t3.medium` |
| Auditor | `honeypot-auditor 1.0.0` |
| Bind address | `127.0.0.1` only |
| Date | 2026-09-22 |
