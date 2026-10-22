import csv, json, os, sys

def base(p):
    return os.path.basename(str(p))

def load(path):
    if not os.path.exists(path):
        sys.exit("Missing " + path + " - run the scan command that creates it first.")
    data = json.load(open(path))
    if isinstance(data, dict):
        data = data.get("findings", data.get("results", []))
    return data

if not os.path.exists("eval/ground_truth.csv"):
    sys.exit("Missing eval/ground_truth.csv (the answer key).")

gt = []
with open("eval/ground_truth.csv", newline="") as f:
    for row in csv.DictReader(f):
        row = {k.strip().lower(): v for k, v in row.items()}
        gt.append((base(row["file"]), int(row["line"])))

def hits(x, g, tol=3):
    try:
        return base(x["file"]) == g[0] and abs(int(x["line"]) - g[1]) <= tol
    except Exception:
        return False

def evaluate(findings):
    posted = [x for x in findings if not x.get("suppressed")]
    supp = [x for x in findings if x.get("suppressed")]
    detected = [g for g in gt if any(hits(x, g) for x in posted)]
    dropped = [g for g in gt if any(hits(x, g) for x in supp)
               and not any(hits(x, g) for x in posted)]
    false_alarms = [x for x in posted if not any(hits(x, g) for g in gt)]
    return len(findings), len(posted), len(detected), len(false_alarms), len(dropped)

a = evaluate(load("eval/a.json"))
b = evaluate(load("eval/b.json"))
red = (a[3] - b[3]) / a[3] * 100 if a[3] else 0

rows = [
    "| Metric | Version A (scanners only) | Version B (scanners + AI) |",
    "|---|---|---|",
    f"| Total findings | {a[0]} | {b[0]} |",
    f"| Findings posted | {a[1]} | {b[1]} |",
    f"| Planted issues in answer key | {len(gt)} | {len(gt)} |",
    f"| Planted issues detected | {a[2]} | {b[2]} |",
    f"| False alarms (posted, not in answer key) | {a[3]} | {b[3]} |",
    f"| Planted issues wrongly suppressed by AI | - | {b[4]} |",
    f"| False-alarm reduction | - | {red:.1f}% |",
]
text = "\n".join(rows)
print(text)
open("eval/results_manual.md", "w").write(text + "\n")
print("\nSaved eval/results_manual.md")
