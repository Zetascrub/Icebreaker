# Icebreaker (v0.1)

First-strike recon scanner with a clean plugin core.

## Quickstart

```bash
# create venv however you like; example with uv:
uv venv && source .venv/bin/activate
uv pip install -e .
```

# scope.txt contains one host per line
echo 192.168.1.1 > scope.txt
echo example.com >> scope.txt

icebreaker scan --targets scope.txt --preset quick

Outputs to runs/<id>-quick/, including summary.md and findings.jsonl.


---

## Run it now

1) Paste the files into your repo exactly as shown.  
2) Create a `scope.txt` with a couple of hosts/IPs.  
3) Create venv and install editable:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

4) Scan

```bash
icebreaker scan --targets scope.txt --preset quick
```