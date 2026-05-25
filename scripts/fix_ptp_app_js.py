from pathlib import Path

p = Path(__file__).resolve().parents[1] / "src" / "ptp_client" / "web" / "static" / "ptp-app.js"
t = p.read_text(encoding="utf-8")
t = t.replace("\\`", "`")
t = t.replace('.join("\\\\n")', '.join("\\n")')
p.write_text(t, encoding="utf-8")
print("fixed", p)
