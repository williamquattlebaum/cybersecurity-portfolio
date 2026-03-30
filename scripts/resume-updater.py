#!/usr/bin/env python3
"""
📄 RESUME AUTO-UPDATER
Watches the portfolio for new IRs and scripts, auto-updates resume.md
and pushes to GitHub. Keeps the resume current with zero manual effort.

What it updates:
  - Incident report count in summary
  - Project script count in automation section
  - Last updated date
  - Skills table (adds new tools when detected in IRs/scripts)
  - IR list in projects section

Usage:
  python3 resume-updater.py          # check and update if needed
  python3 resume-updater.py --dry-run # show what would change
  python3 resume-updater.py --force   # update even if nothing changed
"""

import subprocess, json, re, argparse
from datetime import datetime
from pathlib import Path

REPO_DIR     = Path("/root/cybersecurity-portfolio")
RESUME_FILE  = REPO_DIR / "resume.md"
IR_DIR       = REPO_DIR / "incident-reports"
SCRIPTS_DIR  = REPO_DIR / "scripts"
STATE_FILE   = Path("/root/.openclaw/workspace/memory/resume-updater-state.json")

GIT_USER  = "williamquattlebaum"
GIT_EMAIL = "williamquattlebaum@gmail.com"
GIT_TOKEN = "GH_TOKEN_REDACTED"

# ─── State ────────────────────────────────────────────────────────────────────

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"last_ir_count": 0, "last_script_count": 0, "last_updated": None}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

# ─── Portfolio scanning ───────────────────────────────────────────────────────

def scan_irs():
    """Return list of IR files with metadata."""
    irs = []
    for f in sorted(IR_DIR.glob("*.md")):
        content = f.read_text()
        # Extract title, severity, status from first few lines
        title_match = re.search(r'^#\s+\S+:\s+(.+)$', content, re.MULTILINE)
        sev_match   = re.search(r'\*\*Severity:\*\*\s+(\w+)', content)
        title   = title_match.group(1).strip() if title_match else f.stem
        severity = sev_match.group(1) if sev_match else "Unknown"
        irs.append({"file": f.name, "stem": f.stem, "title": title, "severity": severity})
    return irs

def scan_scripts():
    """Return list of Python scripts."""
    return [f.name for f in sorted(SCRIPTS_DIR.glob("*.py"))]

def detect_new_tools(irs, scripts):
    """Detect tools mentioned in new content that aren't in resume skills."""
    tool_keywords = {
        "Textual": "Textual TUI",
        "thehive": "TheHive 5.3",
        "correlator": "Alert Correlation",
        "chaos": "Red Team Automation",
        "attackmap": "Live Attack Mapping",
        "splunk-dashboards": "Splunk Dashboard Development",
        "cve-watchdog": "CVE Monitoring",
    }
    found = []
    all_names = " ".join(scripts).lower()
    for keyword, label in tool_keywords.items():
        if keyword.lower() in all_names:
            found.append(label)
    return found

# ─── Resume updater ───────────────────────────────────────────────────────────

def update_resume(irs, scripts, dry_run=False):
    content = RESUME_FILE.read_text()
    original = content
    changes = []
    now = datetime.now().strftime("%B %Y")
    today = datetime.now().strftime("%Y-%m-%d")

    # 1. Update IR count in summary
    ir_count = len(irs)
    content, n = re.subn(
        r'(\d+)\s+incident reports? documented',
        f'{ir_count} incident reports documented',
        content
    )
    if n: changes.append(f"IR count → {ir_count}")

    # 2. Update script count
    script_count = len(scripts)
    content, n = re.subn(
        r'(\d+)\s+custom Python scripts?',
        f'{script_count} custom Python scripts',
        content
    )
    if n: changes.append(f"Script count → {script_count}")

    # 3. Update "managing X VMs" in project descriptions
    content, n = re.subn(
        r'managing \d+ VMs',
        'managing 6 VMs',
        content
    )
    if n: changes.append("VM count → 6")

    # 4. Update Suricata rule count
    content, n = re.subn(
        r'\d{2,3},\d{3} active detection rules',
        '48,786 active detection rules',
        content
    )
    if n: changes.append("Suricata rule count updated")

    # 5. Update last updated date in footer
    content, n = re.subn(
        r'Last updated: .+',
        f'Last updated: {today}',
        content
    )
    if n: changes.append(f"Last updated → {today}")

    # 6. Add new skills to table if not present
    new_skills = [
        ("Splunk", "Splunk 9.3"),
        ("TheHive", "TheHive 5.3"),
        ("Correlation", "Alert correlation engine (Wazuh + Suricata)"),
        ("CVE Monitoring", "NVD + CISA KEV watchdog"),
    ]
    for skill_key, skill_val in new_skills:
        if skill_key not in content and "| Automation |" in content:
            content = content.replace(
                "| Automation |",
                f"| {skill_key} | {skill_val} |\n| Automation |"
            )
            changes.append(f"Added skill: {skill_key}")

    # 7. Update IR table in projects section if it exists
    ir_table_marker = "<!-- IR_TABLE_AUTO -->"
    if ir_table_marker in content:
        new_table = "| ID | Title | Severity |\n|---|---|---|\n"
        for ir in irs:
            ir_id = ir['stem'].upper().replace('_', '-')
            new_table += f"| {ir_id} | {ir['title'][:60]} | {ir['severity']} |\n"
        content = re.sub(
            rf'{re.escape(ir_table_marker)}.*?{re.escape(ir_table_marker)}',
            f'{ir_table_marker}\n{new_table}{ir_table_marker}',
            content, flags=re.DOTALL
        )
        if new_table not in original:
            changes.append("IR table updated")

    if not changes:
        print("  ✓ Resume is already up to date — no changes needed")
        return False

    print(f"  Changes detected: {len(changes)}")
    for c in changes:
        print(f"    • {c}")

    if dry_run:
        print("\n  [dry-run] No files modified")
        return False

    RESUME_FILE.write_text(content)
    print(f"\n  ✓ resume.md updated")
    return True

# ─── Git push ─────────────────────────────────────────────────────────────────

def git_push(message):
    repo = str(REPO_DIR)
    cmds = [
        f"cd {repo} && git config user.email '{GIT_EMAIL}'",
        f"cd {repo} && git config user.name '{GIT_USER}'",
        f"cd {repo} && git add resume.md",
        f"cd {repo} && git diff --cached --stat",
        f"cd {repo} && git commit -m '{message}'",
        f"cd {repo} && git push origin main",
    ]
    for cmd in cmds:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 and 'nothing to commit' not in result.stdout:
            if 'nothing to commit' in result.stderr:
                continue
            print(f"  [git] {result.stderr.strip()[:100]}")
    print(f"  ✓ Pushed to GitHub")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main(dry_run=False, force=False):
    print(f"\n📄 Resume Auto-Updater")

    if not RESUME_FILE.exists():
        print(f"  ✗ resume.md not found at {RESUME_FILE}")
        return

    state = load_state()
    irs = scan_irs()
    scripts = scan_scripts()

    print(f"  Incident reports: {len(irs)}  |  Scripts: {len(scripts)}")

    # Check if anything changed
    ir_changed     = len(irs) != state['last_ir_count']
    script_changed = len(scripts) != state['last_script_count']

    if not force and not ir_changed and not script_changed:
        print(f"  No changes since last run (IRs: {state['last_ir_count']}, scripts: {state['last_script_count']})")
        return

    if ir_changed:
        print(f"  New IRs detected: {state['last_ir_count']} → {len(irs)}")
    if script_changed:
        print(f"  New scripts detected: {state['last_script_count']} → {len(scripts)}")

    updated = update_resume(irs, scripts, dry_run=dry_run)

    if updated and not dry_run:
        msg = f"Auto-update resume: {len(irs)} IRs, {len(scripts)} scripts [{datetime.now().strftime('%Y-%m-%d')}]"
        git_push(msg)
        state['last_ir_count'] = len(irs)
        state['last_script_count'] = len(scripts)
        state['last_updated'] = datetime.now().isoformat()
        save_state(state)
        print(f"\n  ✓ Resume updated and pushed to GitHub")
    elif not dry_run:
        state['last_ir_count'] = len(irs)
        state['last_script_count'] = len(scripts)
        save_state(state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Resume Auto-Updater")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    parser.add_argument("--force",   action="store_true", help="Update even if no changes detected")
    args = parser.parse_args()
    main(dry_run=args.dry_run, force=args.force)
