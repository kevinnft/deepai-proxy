# deepai-proxy

OpenAI-compatible proxy ringan (murni Python 3 stdlib, **zero dependency**) untuk menghubungkan **DeepAI Code** (`https://api.deepai.org/deepai_code` — sudah pre-configured di dalam app) ke **9Router**, Cursor, Cline, RooCode, OpenCode, maupun SDK OpenAI standar.

## Apa yang ditangani otomatis?
- **Upstream Base URL sudah disetup otomatis** ke `https://api.deepai.org/deepai_code` — tinggal masukkan UUID API Key DeepAI saja.
- **Translasi Auth Header**: `Authorization` / `x-api-key` dari 9Router otomatis diubah menjadi `Api-Key` DeepAI.
- **Bypass WAF Node.js**: Override `User-Agent: node` agar tidak kena HTTP 400 WAF.
- **Protokol Theos & Fingerprint**: Auto-probe `X-DeepAI-Code-Theos` (lane 4), `X-DeepAI-Code-Instance`, `X-DeepAI-Code-Machine`, plus 2-step check-in `/deepai_code/theos` otomatis.
- **Fix Non-Stream JSON**: Memaksa `stream: false` eksplisit saat non-stream (karena upstream DeepAI default ke SSE kalau field `stream` kosong).
- **Reasoning & Responses Bridge**: Mirror `reasoning` -> `reasoning_content` + konversi otomatis model Responses (`gpt-6-astra`) agar jalan mulus di `/v1/chat/completions`.
- **2 Mode Pemakaian API Key**:
  1. **Direct Pass-Through (tanpa isi config pun jalan!)**: langsung paste UUID API key DeepAI di kolom API Key 9Router.
  2. **Multi-Account Pool (Round-Robin + Failover)**: masukkan 1 atau banyak UUID key lewat Web Dashboard / `DEEPAI_KEYS` / `config.json`, lalu di 9Router isi `PROXY_API_KEY` (default: `deepai-local`).

---

## Install Cepat di VPS (Ubuntu / Debian — systemd auto-start)

```bash
git clone https://github.com/kevinnft/deepai-proxy.git
cd deepai-proxy
chmod +x install-ubuntu.sh
sudo PROXY_API_KEY="password-gateway-kamu" ./install-ubuntu.sh
```

Atau sekalian masukkan key DeepAI saat install (opsional, dipisah koma jika lebih dari satu):

```bash
sudo PROXY_API_KEY="password-gateway-kamu" DEEPAI_KEYS="uuid-key-1,uuid-key-2" ./install-ubuntu.sh
```

Service systemd otomatis menyala di port `1417` (`systemctl status deepai-proxy`).

### Alternatif: Docker Compose di VPS

```bash
git clone https://github.com/kevinnft/deepai-proxy.git
cd deepai-proxy
PROXY_API_KEY="password-gateway-kamu" docker compose up -d --build
```

### Alternatif: Jalan Langsung (Lokal / WSL)

```bash
./run.sh
```

---

## Cara Pakai di 9Router

Tambahkan **OpenAI-Compatible Provider** di 9Router:
- **Base URL**: `http://<IP_VPS_ATAU_127.0.0.1>:1417/v1`
- **API Key**:
  - Langsung isi **UUID API Key DeepAI** kamu (tidak perlu edit config di VPS sama sekali!), **ATAU**
  - Isi nilai `PROXY_API_KEY` kamu (default: `deepai-local`) jika menyimpan pool akun lewat Web Dashboard `http://<IP_VPS>:1417/`.

---

## Environment Variables

| Variable | Default | Fungsi |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `1417` | Port HTTP |
| `PROXY_API_KEY` | `deepai-local` | Key gateway untuk mode pool & login Web Dashboard dari IP publik |
| `ADMIN_TOKEN` | *(ikut `PROXY_API_KEY`)* | Token khusus admin Web Dashboard (opsional) |
| `DEEPAI_KEYS` | *(kosong)* | Daftar UUID key DeepAI dipisah koma |
| `CONFIG_DIR` | `~/.deepai-openai` | Direktori simpan `config.json` & `proxy.log` |

---

## Daftar 22 Model ID

- **Gratis / Unmetered (0 Theos)**:
  `glm-5.3-flash`, `deepseek-v4.1-flash`, `mimo-2.6-flash`, `mimo-2.6-pro`, `qwen-3.8-flash`, `minimax-m3.1-flash`, `solar-mini-4`, `gpt-6-luna`, `crouton-alpha`, `glyph-cluster`, `deepai-cyber`
- **Frontier (Kuota Theos Harian)**:
  `minimax-m3` (2), `glm-5.3` (3), `kimi-k3` (3), `muse-spark-1.3` (6), `gpt-6.1-sol` (10), `gemini-4-argon` (10), `claude-opus-5-5` (15), `muse-wonder` (15), `qwen-3.8-max-prime` (15), `claude-fable-5-2` (20), `gpt-6-astra` (50)
