# CTF Agent

Autonomous CTF (Capture The Flag) solver that races multiple AI models against challenges in parallel. Built in a weekend, we used it to solve all 52/52 challenges and win **1st place at BSidesSF 2026 CTF**.

Built by [Veria Labs](https://verialabs.com), founded by members of [.;,;.](https://ctftime.org/team/222911) (smiley), the [#1 US CTF team on CTFTime in 2024 and 2025](https://ctftime.org/stats/2024/US). We build AI agents that find and exploit real security vulnerabilities for large enterprises.

## Results

| Competition | Challenges Solved | Result |
|-------------|:-:|--------|
| **BSidesSF 2026** | 52/52 (100%) | **1st place ($1,500)** |

The agent solves challenges across all categories — pwn, rev, crypto, forensics, web, and misc.

## How It Works

A **coordinator** LLM manages the competition while **solver swarms** attack individual challenges. Each swarm runs multiple models simultaneously - the first to find the flag wins.

Challenge routing happens per challenge: `select_models_for_challenge()` starts from the default model lineup and can auto-add `browser-use/bu-latest` when the challenge looks browser-heavy and Browser Use prerequisites are available.

```mermaid
flowchart TD
    A[CTFd Platform] --> B[Poller (5s)]
    B --> C[Coordinator LLM<br/>(Claude / Codex)]
    C --> D[Challenge metadata +<br/>model selection]
    D --> E[Challenge swarm]

    E --> F1[Claude SDK solvers<br/>claude-opus-4-6 medium/max]
    E --> F2[Codex solvers<br/>gpt-5.4 / gpt-5.4-mini / gpt-5.3-codex]
    E --> F3[browser-use/bu-latest<br/>auto-enabled for web/browser-heavy challenges]

    F1 --> G[Docker sandbox<br/>pwntools, r2, gdb, python...]
    F2 --> G
    F3 --> H[Host browser<br/>Chrome / Chromium]
    F3 --> G

    H --> I[Interactive web app]
    G --> J[Shell, files, exploit scripts]
```

Each swarm uses an isolated Docker sandbox for CTF tools. Browser Use solvers additionally drive a host browser for interactive web work. Solvers never give up - they keep trying different approaches until the flag is found.

## Quick Start

```bash
# Install
uv sync

# Build sandbox image
docker build -f sandbox/Dockerfile.sandbox -t ctf-sandbox .

# Configure credentials
cp .env.example .env
# Edit .env with your API keys and CTFd token

# Run against a CTFd instance
uv run ctf-solve \
  --ctfd-url https://ctf.example.com \
  --ctfd-token ctfd_your_token \
  --challenges-dir challenges \
  --max-challenges 10 \
  -v
```

## Coordinator Backends

```bash
# Claude SDK coordinator (default)
uv run ctf-solve --coordinator claude ...

# Codex coordinator (GPT-5.4 via JSON-RPC)
uv run ctf-solve --coordinator codex ...
```

## Solver Models

Default model lineup (configurable in `backend/models.py`):

| Model | Provider | Notes |
|-------|----------|-------|
| Claude Opus 4.6 (medium) | Claude SDK | Balanced speed/quality |
| Claude Opus 4.6 (max) | Claude SDK | Deep reasoning |
| GPT-5.4 | Codex | Best overall solver |
| GPT-5.4-mini | Codex | Fast, good for easy challenges |
| GPT-5.3-codex | Codex | Reasoning model (xhigh effort) |

### Opt-In Browser Solver

For browser-heavy web challenges, you can add a Browser Use solver explicitly:

```bash
uv run ctf-solve \
  --models browser-use/bu-latest \
  --challenge challenges/example-web
```

This solver is **not** part of `DEFAULT_MODELS`. It runs Chrome/Chromium on the host, uses Browser Use `0.12.6` with `ChatBrowserUse`, and keeps the existing Docker sandbox for shell commands, local files, and exploit scripts.

### Auto-Enable Browser Solver (Per Challenge)

When running `ctf-solve`, challenge model selection auto-adds `browser-use/bu-latest` **per challenge** when it detects browser-heavy signals (for example web category or HTTP/HTTPS connection info), but only if Browser Use prerequisites are available:

- `BROWSER_USE_API_KEY` is set
- host Chrome/Chromium exists (or `BROWSER_USE_EXECUTABLE_PATH` is set)

You can disable this behavior with:

```env
BROWSER_USE_AUTO_ENABLE=false
```

## Sandbox Tooling

Each solver gets an isolated Docker container pre-loaded with CTF tools:

| Category | Tools |
|----------|-------|
| **Binary** | radare2, GDB, objdump, binwalk, strings, readelf |
| **Pwn** | pwntools, ROPgadget, angr, unicorn, capstone |
| **Crypto** | SageMath, RsaCtfTool, z3, gmpy2, pycryptodome, cado-nfs |
| **Forensics** | volatility3, Sleuthkit (mmls/fls/icat), foremost, exiftool |
| **Stego** | steghide, stegseek, zsteg, ImageMagick, tesseract OCR |
| **Web** | curl, nmap, Python requests, flask |
| **Misc** | ffmpeg, sox, Pillow, numpy, scipy, PyTorch, podman |

## Features

- **Multi-model racing** — multiple AI models attack each challenge simultaneously
- **Auto-spawn** — new challenges detected and attacked automatically
- **Coordinator LLM** — reads solver traces, crafts targeted technical guidance
- **Cross-solver insights** — findings shared between models via message bus
- **Docker sandboxes** — isolated containers with full CTF tooling
- **Operator messaging** — send hints to running solvers mid-competition

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

```env
CTFD_URL=https://ctf.example.com
CTFD_TOKEN=ctfd_your_token
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
BROWSER_USE_API_KEY=
BROWSER_USE_EXECUTABLE_PATH=
BROWSER_USE_HEADLESS=true
BROWSER_USE_AUTO_ENABLE=true
```

All settings can also be passed as environment variables or CLI flags.

## Requirements

- Python 3.14+
- Docker
- API keys for at least one provider (Anthropic, OpenAI, Google, or Browser Use)
- Chrome or Chromium on the host if using `browser-use/*` models
- `BROWSER_USE_API_KEY` if using `browser-use/*` models
- `codex` CLI (for Codex solver/coordinator)
- `claude` CLI (bundled with claude-agent-sdk)

## Acknowledgements

- [es3n1n/Eruditus](https://github.com/es3n1n/Eruditus) — CTFd interaction and HTML helpers in `pull_challenges.py`
