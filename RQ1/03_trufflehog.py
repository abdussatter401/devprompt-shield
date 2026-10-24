import argparse, json, platform, shutil, subprocess, tarfile, tempfile, urllib.request
from pathlib import Path

from common import EVAL_FILE, OUT_DIR, ROOT, binary_metrics, load_eval_set

VERSION = "3.99.3"
ap = argparse.ArgumentParser()
ap.add_argument("--eval-file", default=str(EVAL_FILE))
ap.add_argument("--bin", default=str(ROOT / "bin" / "trufflehog"))
ap.add_argument("--out-dir", default=str(OUT_DIR / "results"))
a = ap.parse_args()

binary = Path(a.bin)
if not binary.exists():
    if platform.system() != "Linux":
        raise SystemExit("auto-download supports Linux only; pass --bin /path/to/trufflehog")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    url = (f"https://github.com/trufflesecurity/trufflehog/releases/download/v{VERSION}/"
           f"trufflehog_{VERSION}_linux_{arch}.tar.gz")
    binary.parent.mkdir(parents=True, exist_ok=True)
    print("downloading", url)
    with tempfile.TemporaryDirectory() as tmp:
        tgz = Path(tmp) / "th.tgz"
        urllib.request.urlretrieve(url, tgz)
        with tarfile.open(tgz) as t:
            t.extract("trufflehog", tmp)
        shutil.move(str(Path(tmp) / "trufflehog"), binary)
    binary.chmod(0o755)

texts, labels = load_eval_set(a.eval_file)
out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="th_prompts_") as work:
    for i, t in enumerate(texts):
        (Path(work) / f"{i:05d}.txt").write_text(t, encoding="utf-8")
    proc = subprocess.run([str(binary), "filesystem", work, "--json", "--no-verification", "--no-update"],
                          capture_output=True, text=True)
(out / "trufflehog_findings.jsonl").write_text(proc.stdout)
if proc.returncode != 0:
    raise SystemExit(f"trufflehog failed ({proc.returncode}):\n{proc.stderr[-2000:]}")

flagged = {}
for line in proc.stdout.splitlines():
    if line.startswith("{"):
        f = json.loads(line)
        path = f.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file")
        if path:
            flagged.setdefault(int(Path(path).stem), []).append(f.get("DetectorName"))
preds = [1 if i in flagged else 0 for i in range(len(texts))]
m = binary_metrics(labels, preds)
m["trufflehog_version"] = VERSION
json.dump(m, open(out / "trufflehog_on_3000.json", "w"), indent=2)
print(f"flagged {m['flagged']} of {len(texts)} prompts")
print(" ".join(f"{k}={m[k]:.3f}" for k in ["F1", "precision", "recall_TPR", "FPR", "accuracy"]),
      f"| TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']}")
