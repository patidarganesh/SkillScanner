import os
import re
import dis
import marshal
import io
import hashlib
import zipfile
import tarfile
import pathlib
from pathlib import Path

READABLE = {
    # Docs
    '.md', '.markdown', '.txt', '.rst', '.adoc',
    # Code
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash',
    '.zsh', '.ps1', '.bat', '.cmd', '.rb', '.go', '.rs',
    '.cpp', '.c', '.h', '.java', '.kt', '.swift', '.php', '.lua',
    # Config / data
    '.json', '.yaml', '.yml', '.toml', '.ini', '.env',
    '.cfg', '.conf', '.xml', '.csv',
    # Web
    '.html', '.css', '.scss', '.svg',
}

# Explicitly skipped binaries / executables / media
SKIP = {
    # Binaries / executables
    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
    # Media
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico',
    '.mp3', '.mp4', '.wav', '.avi', '.mov',
    # Compiled
    '.pyc', '.pyo', '.class', '.o', '.a',
    # Misc binary
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.sqlite', '.db', '.lock',
}

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv',
    'venv', 'env', 'dist', 'build', '.next', '.nuxt',
}

# Suspicious script extensions that should never be hidden in .git, __pycache__, etc.
EXECUTABLE_SCRIPT_EXTS = {
    '.py', '.pyw', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    '.js', '.ts', '.mjs', '.cjs', '.rb', '.php', '.lua', '.vbs',
}

BINARY_EXECUTABLE_EXTS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '.class', '.o', '.a'
}


def extract_strings_from_bytes(data: bytes, min_len: int = 4) -> list:
    """Extract printable ASCII/UTF-8 strings from binary data."""
    try:
        matches = re.findall(b'[\x20-\x7e]{' + str(min_len).encode() + b',}', data)
        results = []
        for m in matches:
            try:
                s = m.decode('utf-8', errors='ignore').strip()
                if len(s) >= min_len:
                    results.append(s)
            except Exception:
                continue
        return results
    except Exception:
        return []


def disassemble_pyc(file_path: Path) -> dict:
    """
    Disassemble a .pyc / .pyo file into readable bytecode instructions
    and extract referenced constants, variable names, and calls.
    """
    result = {
        "success": False,
        "disassembly": "",
        "constants": [],
        "names": [],
        "error": None
    }
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Python 3.7+ pyc header is 16 bytes. Python 3.6 was 12 bytes. Older was 8 bytes.
        code = None
        for offset in [16, 12, 8, 4, 0]:
            try:
                loaded = marshal.loads(data[offset:])
                if hasattr(loaded, 'co_code'):
                    code = loaded
                    break
            except Exception:
                continue

        if not code:
            result["error"] = "Could not parse code object from bytecode header"
            return result

        out = io.StringIO()
        dis.dis(code, file=out)
        result["disassembly"] = out.getvalue()

        # Extract constants and names (recursively inspect nested code objects)
        consts = []
        names = set(getattr(code, 'co_names', ()))

        def collect_code_info(co):
            for c in getattr(co, 'co_consts', ()):
                if isinstance(c, (str, bytes, int, float)) and c not in consts:
                    consts.append(str(c))
                elif hasattr(c, 'co_code'):
                    names.update(getattr(c, 'co_names', ()))
                    collect_code_info(c)

        collect_code_info(code)
        result["constants"] = consts[:100]
        result["names"] = sorted(list(names))[:100]
        result["success"] = True
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def inspect_binary_file(file_path: Path, max_bytes: int = 2 * 1024 * 1024) -> dict:
    """Extract strings and scan for security indicators in a binary file."""
    info = {
        "size_bytes": 0,
        "sha256": "",
        "suspicious_urls": [],
        "suspicious_ips": [],
        "suspicious_commands": [],
        "sensitive_targets": [],
        "sample_strings": []
    }
    try:
        size = file_path.stat().st_size
        info["size_bytes"] = size
        with open(file_path, 'rb') as f:
            head_data = f.read(max_bytes)

        info["sha256"] = hashlib.sha256(head_data).hexdigest()
        strings = extract_strings_from_bytes(head_data, min_len=4)
        info["sample_strings"] = strings[:60]

        url_pattern = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        cmd_pattern = re.compile(r'\b(powershell|cmd\.exe|/bin/sh|/bin/bash|curl|wget|nc\s|chmod\s|execve|CreateProcess|VirtualAlloc|socket|system)\b', re.IGNORECASE)
        sens_pattern = re.compile(r'(/etc/passwd|id_rsa|id_ed25519|\.env|API_KEY|TOKEN|PASSWORD|SECRET)', re.IGNORECASE)

        for s in strings:
            for u in url_pattern.findall(s):
                if u not in info["suspicious_urls"]:
                    info["suspicious_urls"].append(u)
            for ip in ip_pattern.findall(s):
                if not ip.startswith("0.0.") and not ip.startswith("127.0.0.1") and ip not in info["suspicious_ips"]:
                    info["suspicious_ips"].append(ip)
            if cmd_pattern.search(s) and s not in info["suspicious_commands"]:
                info["suspicious_commands"].append(s[:100])
            if sens_pattern.search(s) and s not in info["sensitive_targets"]:
                info["sensitive_targets"].append(s[:100])

        info["suspicious_urls"] = info["suspicious_urls"][:15]
        info["suspicious_ips"] = info["suspicious_ips"][:15]
        info["suspicious_commands"] = info["suspicious_commands"][:20]
        info["sensitive_targets"] = info["sensitive_targets"][:20]
    except Exception as e:
        info["error"] = str(e)
    return info


def inspect_archive_file(file_path: Path) -> dict:
    """Inspect contents of an archive file (.zip, .tar, etc.)."""
    info = {
        "file_count": 0,
        "entries": [],
        "executable_entries": []
    }
    ext = file_path.suffix.lower()
    try:
        if ext == '.zip':
            with zipfile.ZipFile(file_path, 'r') as z:
                names = z.namelist()
                info["file_count"] = len(names)
                info["entries"] = names[:50]
                for n in names:
                    n_ext = Path(n).suffix.lower()
                    if n_ext in EXECUTABLE_SCRIPT_EXTS or n_ext in BINARY_EXECUTABLE_EXTS:
                        info["executable_entries"].append(n)
        elif ext in ('.tar', '.gz', '.bz2', '.tgz'):
            with tarfile.open(file_path, 'r:*') as t:
                names = t.getnames()
                info["file_count"] = len(names)
                info["entries"] = names[:50]
                for n in names:
                    n_ext = Path(n).suffix.lower()
                    if n_ext in EXECUTABLE_SCRIPT_EXTS or n_ext in BINARY_EXECUTABLE_EXTS:
                        info["executable_entries"].append(n)
    except Exception as e:
        info["error"] = str(e)
    return info


def generate_tree(dir_path: Path, prefix: str = "", is_last: bool = True, is_root: bool = True) -> str:
    if not dir_path.is_dir():
        return ""
    
    tree = ""
    if is_root:
        tree += f"{dir_path.name}/\n"
        
    try:
        items = list(dir_path.iterdir())
        valid_items = []
        for item in items:
            if item.is_dir() and item.name in SKIP_DIRS:
                continue
            valid_items.append(item)
            
        valid_items.sort(key=lambda x: (not x.is_dir(), x.name.lower()))
        
        for i, item in enumerate(valid_items):
            last = (i == len(valid_items) - 1)
            marker = "└── " if last else "├── "
            
            if item.is_dir():
                tree += f"{prefix}{marker}{item.name}/\n"
                new_prefix = prefix + ("    " if last else "│   ")
                tree += generate_tree(item, new_prefix, last, is_root=False)
            else:
                tree += f"{prefix}{marker}{item.name}\n"
    except Exception:
        pass
    
    return tree


def find_references_in_text(content: str) -> list:
    """Find references to skipped dirs or skipped file types in file text."""
    refs = []
    
    # 1. Look for paths pointing into skipped directories
    # e.g., .git/something, .venv/something, node_modules/something
    skip_dir_pattern = re.compile(
        r'(?:[\'"\s(=]|^)(\.(?:git|venv)|(?:node_modules|__pycache__|venv|env|dist|build)/[^\s\'"`;\)>\]}]+)',
        re.IGNORECASE
    )
    for m in skip_dir_pattern.finditer(content):
        val = m.group(1).strip().replace('\\', '/')
        if val not in refs:
            refs.append(val)

    # 2. Look for execution commands: python foo, bash foo, sh foo, etc.
    cmd_pattern = re.compile(
        r'\b(?:python[0-9.]*|bash|sh|zsh|node|node\.exe|powershell|cmd|cmd\.exe|exec|source|\./)\s+([^\s\'"`;|&>]+)',
        re.IGNORECASE
    )
    for m in cmd_pattern.finditer(content):
        val = m.group(1).strip().replace('\\', '/')
        if val not in refs and not val.startswith('-'):
            refs.append(val)

    # 3. Look for mentions of skipped extensions
    ext_pattern = re.compile(
        r'([a-zA-Z0-9_\-./\\]+\.(?:exe|dll|so|dylib|bin|dat|pyc|pyo|class|o|a|zip|tar|gz|rar|7z))\b',
        re.IGNORECASE
    )
    for m in ext_pattern.finditer(content):
        val = m.group(1).strip().replace('\\', '/')
        if val not in refs:
            refs.append(val)

    return refs


def scan(path: str) -> dict:
    target = Path(path).resolve()
    
    result = {
        "input_type": "folder" if target.is_dir() else "file",
        "name": target.name,
        "total_files_found": 0,
        "readable_files": 0,
        "skipped_files": 0,
        "file_tree": "",
        "files": [],
        "skipped": [],
        "security_warnings": [],
        "static_findings": [],
        "cross_references": []
    }
    
    finding_id = 1

    def add_static_finding(category: str, severity: str, title: str, description: str, evidence: str, location: str, recommendation: str):
        nonlocal finding_id
        result["static_findings"].append({
            "id": finding_id,
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "location": location,
            "recommendation": recommendation
        })
        finding_id += 1

    if target.is_dir():
        result["file_tree"] = generate_tree(target).strip()
    else:
        result["file_tree"] = target.name

    processed_paths = set()

    def process_readable_file(file_path: Path, rel_path: str, special_note: str = ""):
        result["total_files_found"] += 1
        processed_paths.add(str(file_path.resolve()))
        ext = file_path.suffix.lower()

        try:
            size_bytes = file_path.stat().st_size
            content = ""
            truncated = False

            if size_bytes > 50 * 1024:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(8000)
                content += f"\n... [TRUNCATED — file is {size_bytes//1024}kb, showing first 8000 chars]"
                truncated = True
            else:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

            if special_note:
                content = f"# [SECURITY WARNING: {special_note}]\n" + content

            result["readable_files"] += 1
            result["files"].append({
                "relative_path": rel_path,
                "extension": ext,
                "size_bytes": size_bytes,
                "content": content,
                "truncated": truncated,
                "special_note": special_note
            })
        except Exception as e:
            result["skipped_files"] += 1
            result["skipped"].append({
                "relative_path": rel_path,
                "reason": f"read error: {str(e)}"
            })

    def process_skipped_file(file_path: Path, rel_path: str):
        """Analyze skipped or binary files (.pyc disassembly, binary strings, archive inspection)."""
        result["total_files_found"] += 1
        processed_paths.add(str(file_path.resolve()))
        ext = file_path.suffix.lower()
        size_bytes = file_path.stat().st_size

        # 1. Bytecode handling (.pyc / .pyo)
        if ext in ('.pyc', '.pyo'):
            pyc_info = disassemble_pyc(file_path)
            if pyc_info["success"]:
                dis_content = (
                    f"# [DISASSEMBLED PYTHON BYTECODE FOR: {rel_path}]\n"
                    f"# Constants: {', '.join(pyc_info['constants'][:40])}\n"
                    f"# Variable / Function Names: {', '.join(pyc_info['names'][:40])}\n\n"
                    f"{pyc_info['disassembly'][:10000]}"
                )
                if len(pyc_info['disassembly']) > 10000:
                    dis_content += "\n... [TRUNCATED DISASSEMBLY]"

                result["readable_files"] += 1
                result["files"].append({
                    "relative_path": f"{rel_path} [Bytecode Disassembly]",
                    "extension": ext,
                    "size_bytes": size_bytes,
                    "content": dis_content,
                    "truncated": len(pyc_info['disassembly']) > 10000,
                    "special_note": "Disassembled bytecode analyzed directly"
                })

                # Check if matching source .py exists
                expected_py = None
                if target.is_dir():
                    clean_name = file_path.stem.split('.')[0] + '.py'
                    cand1 = file_path.parent / clean_name
                    cand2 = file_path.parent.parent / clean_name
                    if cand1.exists() or cand2.exists():
                        expected_py = True

                if not expected_py:
                    add_static_finding(
                        category="obfuscated_code",
                        severity="high",
                        title="Orphan compiled bytecode (.pyc) without source",
                        description=f"File {rel_path} is compiled Python bytecode distributed without matching .py source code. Malicious packages often ship pre-compiled bytecode to hide logic from static code inspection.",
                        evidence=f"Bytecode file: {rel_path}",
                        location=rel_path,
                        recommendation="Require full readable .py source code and verify bytecode matches source."
                    )
            else:
                result["skipped_files"] += 1
                result["skipped"].append({
                    "relative_path": rel_path,
                    "reason": f"bytecode parse error ({ext})"
                })
            return

        # 2. Native Executable / Dynamic Library / Binary
        if ext in BINARY_EXECUTABLE_EXTS or ext in ('.bin', '.dat'):
            bin_info = inspect_binary_file(file_path)
            evidence_items = []
            if bin_info.get("suspicious_urls"):
                evidence_items.append(f"URLs: {', '.join(bin_info['suspicious_urls'])}")
            if bin_info.get("suspicious_commands"):
                evidence_items.append(f"Commands: {', '.join(bin_info['suspicious_commands'][:5])}")
            if bin_info.get("sensitive_targets"):
                evidence_items.append(f"Sensitive targets: {', '.join(bin_info['sensitive_targets'][:5])}")

            sev = "critical" if (bin_info.get("suspicious_urls") or bin_info.get("suspicious_commands")) else "high"
            add_static_finding(
                category="supply_chain_risk",
                severity=sev,
                title=f"Embedded executable binary ({ext}) detected",
                description=f"Skill package bundles opaque binary executable '{rel_path}' ({size_bytes} bytes). AI skills should not ship compiled native binaries as they can execute arbitrary machine code with user privileges.",
                evidence=" | ".join(evidence_items) if evidence_items else f"Binary file SHA256: {bin_info.get('sha256')}",
                location=rel_path,
                recommendation=f"Remove binary {rel_path} or replace with transparent, auditable open-source scripts."
            )

            # Also provide extracted strings to file dump so AI can inspect them
            bin_summary = (
                f"# [BINARY METADATA & EXTRACTED STRINGS: {rel_path}]\n"
                f"# Size: {size_bytes} bytes | SHA256: {bin_info.get('sha256')}\n"
                f"# Detected URLs: {bin_info.get('suspicious_urls')}\n"
                f"# Detected Commands: {bin_info.get('suspicious_commands')}\n"
                f"# Sample extracted strings:\n" +
                "\n".join(bin_info.get("sample_strings", []))
            )
            result["readable_files"] += 1
            result["files"].append({
                "relative_path": f"{rel_path} [Binary Strings & Metadata]",
                "extension": ext,
                "size_bytes": size_bytes,
                "content": bin_summary,
                "truncated": False,
                "special_note": "Opaque binary file inspected for strings"
            })
            return

        # 3. Archives (.zip, .tar, etc.)
        if ext in ('.zip', '.tar', '.gz', '.bz2', '.7z', '.rar'):
            arch_info = inspect_archive_file(file_path)
            if arch_info.get("executable_entries"):
                add_static_finding(
                    category="malware",
                    severity="high",
                    title="Archive contains embedded scripts or executables",
                    description=f"Archive '{rel_path}' contains executable files ({', '.join(arch_info['executable_entries'])}). Attackers frequently hide payloads inside archives to evade text scanners.",
                    evidence=f"Entries: {', '.join(arch_info['executable_entries'])}",
                    location=rel_path,
                    recommendation="Extract and audit all archive contents or avoid shipping compressed executable bundles."
                )
            result["skipped_files"] += 1
            result["skipped"].append({
                "relative_path": rel_path,
                "reason": f"archive file ({ext}, {arch_info.get('file_count', 0)} files inside)"
            })
            return

        # 4. Standard media / documents / databases
        result["skipped_files"] += 1
        result["skipped"].append({
            "relative_path": rel_path,
            "reason": f"skipped file type ({ext})"
        })

    # --- PRIMARY WALK ---
    if target.is_file():
        ext = target.suffix.lower()
        if ext in SKIP:
            process_skipped_file(target, target.name)
        else:
            process_readable_file(target, target.name)
    elif target.is_dir():
        # 1. Walk regular files (skipping standard skip_dirs initially)
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.git')]
            root_path = Path(root)
            for file in files:
                file_path = root_path / file
                try:
                    rel_path = str(file_path.relative_to(target)).replace('\\', '/')
                except ValueError:
                    rel_path = file_path.name

                ext = file_path.suffix.lower()
                if ext in SKIP:
                    process_skipped_file(file_path, rel_path)
                else:
                    process_readable_file(file_path, rel_path)

        # 2. DEEP AUDIT OF SKIPPED DIRECTORIES (Issue #2: Skipped directories bypass)
        for root, dirs, files in os.walk(target):
            root_path = Path(root)
            try:
                rel_root = str(root_path.relative_to(target)).replace('\\', '/')
            except ValueError:
                rel_root = ""

            path_parts = rel_root.split('/') if rel_root else []
            in_skipped_dir = any(p in SKIP_DIRS or p.startswith('.git') for p in path_parts)
            
            if in_skipped_dir:
                # We are inside a skipped directory!
                for file in files:
                    file_path = root_path / file
                    try:
                        rel_path = str(file_path.relative_to(target)).replace('\\', '/')
                    except ValueError:
                        rel_path = file_path.name

                    ext = file_path.suffix.lower()

                    # Check for anomalous scripts or executables in .git
                    if '.git' in path_parts or rel_path.startswith('.git/'):
                        # Inside .git: standard files are HEAD, config, refs, objects, index, etc.
                        is_hook = 'hooks' in path_parts
                        if is_hook:
                            # Active git hook that is NOT sample
                            if not file.endswith('.sample') and not file.endswith('.txt'):
                                add_static_finding(
                                    category="malware",
                                    severity="high",
                                    title="Active Git hook detected in .git/hooks",
                                    description=f"Skill package contains active git hook '{rel_path}'. Git hooks automatically run shell commands upon git actions (commit, checkout, push), which can trigger unexpected command execution.",
                                    evidence=f"Hook: {rel_path}",
                                    location=rel_path,
                                    recommendation="Remove unneeded git hooks from skill packages."
                                )
                                process_readable_file(file_path, rel_path, special_note="ACTIVE GIT HOOK IN .git/hooks")
                        elif ext in EXECUTABLE_SCRIPT_EXTS or ext in BINARY_EXECUTABLE_EXTS:
                            add_static_finding(
                                category="malware",
                                severity="critical",
                                title="Malicious script hidden inside .git directory",
                                description=f"Skill package contains executable script '{rel_path}' placed directly inside the .git directory. Standard git repositories never contain code scripts in .git. This is a deliberate evasion technique.",
                                evidence=f"Script in .git: {rel_path}",
                                location=rel_path,
                                recommendation=f"Delete hidden file {rel_path} immediately."
                            )
                            if ext in EXECUTABLE_SCRIPT_EXTS:
                                process_readable_file(file_path, rel_path, special_note="HIDDEN SCRIPT IN .git DIRECTORY")
                            else:
                                process_skipped_file(file_path, rel_path)

                    # Check for anomalous scripts in __pycache__
                    elif '__pycache__' in path_parts:
                        if ext in EXECUTABLE_SCRIPT_EXTS and ext not in ('.pyc', '.pyo'):
                            add_static_finding(
                                category="obfuscated_code",
                                severity="high",
                                title="Script hidden inside __pycache__ directory",
                                description=f"Found script '{rel_path}' placed inside __pycache__. This directory is expected to hold compiled bytecode, not raw scripts.",
                                evidence=f"File: {rel_path}",
                                location=rel_path,
                                recommendation=f"Remove unexpected script {rel_path} from cache directory."
                            )
                            process_readable_file(file_path, rel_path, special_note="HIDDEN SCRIPT IN __pycache__")

        # 3. CROSS-REFERENCE DETECTION (Connecting SKILL.md / scripts to skipped targets)
        # Scan all readable files collected so far to see if they reference or execute files in skipped dirs or skipped types
        for f in list(result["files"]):
            file_content = f.get("content", "")
            source_file = f.get("relative_path", "")

            refs = find_references_in_text(file_content)
            for ref in refs:
                ref_clean = ref.strip().strip("'\"").replace('\\', '/')
                # Check if this reference targets a skipped directory or skipped file type
                is_targeting_skip_dir = any(ref_clean.startswith(sd + '/') or f"/{sd}/" in ref_clean for sd in SKIP_DIRS)
                is_targeting_skip_dir = is_targeting_skip_dir or ref_clean.startswith('.git/') or '/.git/' in ref_clean
                
                ref_ext = Path(ref_clean).suffix.lower()
                is_targeting_skip_file = ref_ext in SKIP

                if is_targeting_skip_dir or is_targeting_skip_file:
                    result["cross_references"].append({
                        "source": source_file,
                        "target": ref_clean,
                        "type": "skipped_directory" if is_targeting_skip_dir else "skipped_file_type"
                    })

                    # Try to locate the referenced file on disk relative to target
                    cand_paths = [
                        target / ref_clean,
                        target / ref_clean.lstrip('/'),
                        (target / source_file).parent / ref_clean
                    ]
                    resolved_file = None
                    for cand in cand_paths:
                        try:
                            if cand.exists() and cand.is_file():
                                resolved_file = cand.resolve()
                                break
                        except Exception:
                            continue

                    # If file exists on disk and was not processed yet, PULL IT IN!
                    if resolved_file and str(resolved_file) not in processed_paths:
                        try:
                            res_rel = str(resolved_file.relative_to(target)).replace('\\', '/')
                        except ValueError:
                            res_rel = resolved_file.name

                        target_ext = resolved_file.suffix.lower()
                        if target_ext in SKIP:
                            process_skipped_file(resolved_file, res_rel)
                        else:
                            process_readable_file(
                                resolved_file,
                                res_rel,
                                special_note=f"REFERENCED FROM {source_file} (TARGET IN SKIPPED DIRECTORY)"
                            )

                    # Generate static threat finding for this suspicious reference
                    if is_targeting_skip_dir:
                        add_static_finding(
                            category="suspicious_behavior",
                            severity="high",
                            title=f"Code or instruction references file in skipped directory ({ref_clean})",
                            description=f"File '{source_file}' references or executes '{ref_clean}', which resides inside a skipped directory. Attackers use this pattern to run code from uninspected folders.",
                            evidence=f"Reference in {source_file}: {ref_clean}",
                            location=f"{source_file} -> {ref_clean}",
                            recommendation="Do not execute files located in hidden, system, or library folders (.git, .venv, etc.)."
                        )
                    elif is_targeting_skip_file:
                        add_static_finding(
                            category="suspicious_behavior",
                            severity="medium" if ref_ext in ('.zip', '.tar') else "high",
                            title=f"Execution or loading of skipped file ({ref_clean})",
                            description=f"File '{source_file}' references or executes '{ref_clean}' with extension {ref_ext}. Executing binary, compiled, or compressed files bypasses standard source code inspection.",
                            evidence=f"Reference in {source_file}: {ref_clean}",
                            location=f"{source_file} -> {ref_clean}",
                            recommendation=f"Audit {ref_clean} thoroughly or replace with auditable source files."
                        )

    return result
