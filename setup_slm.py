#!/usr/bin/env python3
"""
setup_slm.py — ThreatMap Infra SLM setup helper

Downloads the GGUF model for local AI triage.
Run this once before your first scan to avoid download delays mid-scan.

Usage:
  python3 setup_slm.py              # downloads default (Qwen2.5-1.5B, ~1 GB)
  python3 setup_slm.py --phi3       # downloads Phi-3-mini instead (~2.2 GB, better quality)
  python3 setup_slm.py --list       # show available models
  python3 setup_slm.py --check      # check what's already installed
"""

import sys
import os
from pathlib import Path

SLM_CACHE_DIR = Path.home() / ".threatmap" / "models"

MODELS = {
    "qwen-1.5b": {
        "repo_id":     "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        "filename":    "qwen2.5-1.5b-instruct-q4_k_m.gguf",
        "size":        "~1.0 GB",
        "ram_needed":  "~1.5 GB",
        "description": "Qwen2.5-1.5B Instruct (Q4_K_M) — Default. VM-safe, fast CPU inference.",
    },
    "phi3-mini": {
        "repo_id":     "microsoft/Phi-3-mini-4k-instruct-gguf",
        "filename":    "Phi-3-mini-4k-instruct-q4.gguf",
        "size":        "~2.2 GB",
        "ram_needed":  "~3.0 GB",
        "description": "Phi-3-mini-4k Instruct (Q4) — Higher quality, needs 6 GB+ system RAM.",
    },
}


def check_deps() -> bool:
    missing = []
    try:
        import llama_cpp
    except ImportError:
        missing.append("llama-cpp-python")
    try:
        import huggingface_hub
    except ImportError:
        missing.append("huggingface_hub")

    if missing:
        print("\n[!] Missing dependencies:")
        for m in missing:
            print(f"    pip install {m}")
        print("\nInstall all at once:")
        print("    pip install llama-cpp-python huggingface_hub\n")
        return False
    return True


def list_models() -> None:
    print("\nAvailable SLM models:\n")
    for key, m in MODELS.items():
        installed = (SLM_CACHE_DIR / m["filename"]).exists()
        status = "✔ installed" if installed else "○ not downloaded"
        print(f"  [{key}]  {status}")
        print(f"    {m['description']}")
        print(f"    Download: {m['size']}   RAM required: {m['ram_needed']}")
        print(f"    File: {SLM_CACHE_DIR / m['filename']}\n")


def check_installed() -> None:
    print(f"\nModel cache: {SLM_CACHE_DIR}\n")
    any_found = False
    for key, m in MODELS.items():
        path = SLM_CACHE_DIR / m["filename"]
        if path.exists():
            size_gb = path.stat().st_size / 1e9
            print(f"  ✔  {key}  ({size_gb:.2f} GB)  →  {path}")
            any_found = True
    if not any_found:
        print("  No models downloaded yet.")
        print(f"  Run: python3 setup_slm.py")
    print()


def download(preset: str = "qwen-1.5b") -> None:
    if not check_deps():
        sys.exit(1)

    m = MODELS.get(preset)
    if not m:
        print(f"[!] Unknown preset: {preset}")
        print(f"    Available: {', '.join(MODELS.keys())}")
        sys.exit(1)

    SLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = SLM_CACHE_DIR / m["filename"]

    if dest.exists():
        size_gb = dest.stat().st_size / 1e9
        print(f"\n✔  Already downloaded: {m['filename']} ({size_gb:.2f} GB)")
        print(f"   Location: {dest}\n")
        return

    print(f"\nDownloading: {m['description']}")
    print(f"  Source : {m['repo_id']}")
    print(f"  File   : {m['filename']}")
    print(f"  Size   : {m['size']}")
    print(f"  Saving → {SLM_CACHE_DIR}\n")
    print("This is a one-time download. Please wait...\n")

    from huggingface_hub import hf_hub_download
    try:
        path = hf_hub_download(
            repo_id=m["repo_id"],
            filename=m["filename"],
            local_dir=str(SLM_CACHE_DIR),
            local_dir_use_symlinks=False,
        )
        size_gb = Path(path).stat().st_size / 1e9
        print(f"\n✔  Download complete!")
        print(f"   File   : {path}")
        print(f"   Size   : {size_gb:.2f} GB")
        print(f"\nThreatMap Infra will now use local SLM triage automatically.")
        print(f"No API keys or Ollama required.\n")
    except KeyboardInterrupt:
        print("\n[!] Download interrupted.")
        sys.exit(1)
    except Exception as exc:
        print(f"\n[!] Download failed: {exc}")
        print(f"\nManual download:")
        print(f"  URL  : https://huggingface.co/{m['repo_id']}/resolve/main/{m['filename']}")
        print(f"  Save : {SLM_CACHE_DIR / m['filename']}\n")
        sys.exit(1)


def main() -> None:
    args = sys.argv[1:]

    if "--list" in args:
        list_models()
    elif "--check" in args:
        check_installed()
    elif "--phi3" in args:
        download("phi3-mini")
    else:
        download("qwen-1.5b")


if __name__ == "__main__":
    main()
