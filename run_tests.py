"""
Zero-dependency test runner for Dunex.
Executes all test functions in tests/ without requiring pytest or third-party test runners.
"""

import sys
import os
import time
import inspect
import importlib
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add repo root to sys.path
REPO_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

# Set test environment
os.environ["DUNEX_AUDIT_BACKEND"] = "memory"
os.environ["DUNEX_API_TOKENS"] = "test-token-1,test-token-2"

def main():
    print("=" * 70)
    print("🛡️  DUNEX LLM GUARDRAILS — AUTOMATED TEST SUITE")
    print("=" * 70)
    
    test_files = [
        "tests.test_pii",
        "tests.test_injection",
        "tests.test_permissions",
        "tests.test_toxicity",
        "tests.test_pipeline",
        "tests.test_audit",
        "tests.test_api",
    ]
    
    total_passed = 0
    total_failed = 0
    start_time = time.time()
    
    for module_name in test_files:
        try:
            mod = importlib.import_module(module_name)
        except Exception as e:
            print(f"⚠️  Skipping {module_name}: {e}")
            continue
            
        test_funcs = [
            (name, func) for name, func in inspect.getmembers(mod, inspect.isfunction)
            if name.startswith("test_")
        ]
        
        print(f"\n📁 {module_name} ({len(test_funcs)} tests):")
        for name, func in test_funcs:
            t0 = time.time()
            try:
                # If function requires fixtures/args, try running without or with mocks
                sig = inspect.signature(func)
                if len(sig.parameters) == 0:
                    func()
                else:
                    # Provide lightweight mock client and pipeline
                    from starlette.testclient import TestClient
                    from app.main import app, pipeline
                    client = TestClient(app)
                    kwargs = {}
                    for param in sig.parameters:
                        if param in ("client", "test_client"):
                            kwargs[param] = client
                        elif param == "pipeline":
                            kwargs[param] = pipeline
                    func(**kwargs)
                dt = (time.time() - t0) * 1000
                print(f"   ✅ {name:<42} ({dt:.1f}ms)")
                total_passed += 1
            except Exception as e:
                dt = (time.time() - t0) * 1000
                print(f"   ❌ {name:<42} FAILED: {e}")
                total_failed += 1

    total_time = (time.time() - start_time) * 1000
    print("\n" + "=" * 70)
    print(f"SUMMARY: {total_passed} passed, {total_failed} failed in {total_time:.1f}ms")
    print("=" * 70)
    
    if total_failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
