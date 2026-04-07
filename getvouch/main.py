import os
import re

def run_vouch():
    print("🛡️  VOUCH v0.0.1 // The Integrity Layer")
    print("🕵️  Scanning for 'Ghost' Secrets (API Keys)...")
    
    # 1. Define the "Ghosts" we want to find
    patterns = {
        "OpenAI Key": r"sk-[a-zA-Z0-9]{32,}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}"
    }

    found_anything = False
    
    # 2. Search through every file in the folder
    for root, dirs, files in os.walk("."):
        for file in files:
            # We only scan code and text files
            if file.endswith((".py", ".js", ".env", ".txt")) and not root.startswith("./."):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()
                        for label, pattern in patterns.items():
                            if re.search(pattern, content):
                                print(f"🚨 ALERT: Potential {label} found in {file_path}!")
                                found_anything = True
                except Exception:
                    pass

    # 3. Report the Vibe Score
    if not found_anything:
        print("✅ The vibe is clean. No secrets exposed.")
    else:
        print("\n❌ SCAN FAILED: Remove these secrets before pushing to GitHub!")

# 4. This makes sure the scan runs when you type 'vouch'
if __name__ == "__main__":
    run_vouch()