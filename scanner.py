import os
import pathlib
from pathlib import Path

READABLE = {
    # Docs
    '.md', '.markdown', '.txt', '.rst', '.adoc',
    # Code
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash',
    '.zsh', '.ps1', '.rb', '.go', '.rs', '.cpp', '.c',
    '.h', '.java', '.kt', '.swift', '.php', '.lua',
    # Config / data
    '.json', '.yaml', '.yml', '.toml', '.ini', '.env',
    '.cfg', '.conf', '.xml', '.csv',
    # Web
    '.html', '.css', '.scss', '.svg',
}

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
        "skipped": []
    }
    
    if target.is_dir():
        result["file_tree"] = generate_tree(target).strip()
    else:
        result["file_tree"] = target.name
        
    def process_file(file_path: Path, rel_path: str):
        result["total_files_found"] += 1
        
        # Check explicit skip lists
        ext = file_path.suffix.lower()
        if ext in SKIP:
            result["skipped_files"] += 1
            result["skipped"].append({
                "relative_path": rel_path,
                "reason": f"binary file ({ext})"
            })
            return
            
        if ext and ext not in READABLE:
            pass # Try to read anyway if not in skip, but if string decode fails it will be skipped
            
        try:
            size_bytes = file_path.stat().st_size
            if size_bytes > 50 * 1024:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(8000)
                content += f"\n... [TRUNCATED — file is {size_bytes//1024}kb, showing first 8000 chars]"
                truncated = True
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                truncated = False
                
            result["readable_files"] += 1
            result["files"].append({
                "relative_path": rel_path,
                "extension": ext,
                "size_bytes": size_bytes,
                "content": content,
                "truncated": truncated
            })
        except UnicodeDecodeError:
            try:
                # Fallback to latin-1
                if size_bytes > 50 * 1024:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        content = f.read(8000)
                    content += f"\n... [TRUNCATED — file is {size_bytes//1024}kb, showing first 8000 chars]"
                    truncated = True
                else:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                    truncated = False
                    
                result["readable_files"] += 1
                result["files"].append({
                    "relative_path": rel_path,
                    "extension": ext,
                    "size_bytes": size_bytes,
                    "content": content,
                    "truncated": truncated
                })
            except Exception as e:
                result["skipped_files"] += 1
                result["skipped"].append({
                    "relative_path": rel_path,
                    "reason": f"encoding error / unreadable: {str(e)}"
                })
        except Exception as e:
            result["skipped_files"] += 1
            result["skipped"].append({
                "relative_path": rel_path,
                "reason": str(e)
            })

    if target.is_file():
        process_file(target, target.name)
    elif target.is_dir():
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.git')]
            root_path = Path(root)
            for file in files:
                file_path = root_path / file
                try:
                    rel_path = str(file_path.relative_to(target)).replace('\\', '/')
                except ValueError:
                    rel_path = file_path.name
                process_file(file_path, rel_path)
                
    return result
