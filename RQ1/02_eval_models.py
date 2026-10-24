import argparse, csv, glob, statistics as st
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import EVAL_FILE, MAX_LENGTH, OUT_DIR, binary_metrics, load_eval_set

ap = argparse.ArgumentParser()
ap.add_argument("--models-dir", default=str(OUT_DIR / "models"))
ap.add_argument("--eval-file", default=str(EVAL_FILE))
ap.add_argument("--out", default=str(OUT_DIR / "results" / "models_on_3000.csv"))
ap.add_argument("--batch-size", type=int, default=32)
a = ap.parse_args()

texts, labels = load_eval_set(a.eval_file)
device = "cuda" if torch.cuda.is_available() else "cpu"
rows = []
for ckpt in sorted(glob.glob(f"{a.models_dir}/*/*/seed_*")):
    ckpt = Path(ckpt)
    if not (ckpt / "model.safetensors").exists():
        continue
    src, model_name, seed = ckpt.parts[-3], ckpt.parts[-2], int(ckpt.name.split("_")[1])
    tok = AutoTokenizer.from_pretrained(ckpt)
    model = AutoModelForSequenceClassification.from_pretrained(ckpt).to(device).eval()
    if device == "cuda":
        model = model.half()
    preds = []
    with torch.no_grad():
        for i in range(0, len(texts), a.batch_size):
            b = tok(texts[i:i + a.batch_size], truncation=True, padding="max_length",
                    max_length=MAX_LENGTH, return_tensors="pt").to(device)
            preds += model(**b).logits.argmax(1).tolist()
    m = binary_metrics(labels, preds)
    rows.append({"label_source": src, "model": model_name, "seed": seed, **m})
    print(f"{src:5s} {model_name:16s} seed {seed:<4d} F1={m['F1']:.3f} P={m['precision']:.3f} "
          f"TPR={m['recall_TPR']:.3f} FPR={m['FPR']:.3f}")
    del model
    if device == "cuda":
        torch.cuda.empty_cache()

if not rows:
    raise SystemExit(f"no checkpoints found under {a.models_dir}")
Path(a.out).parent.mkdir(parents=True, exist_ok=True)
with open(a.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

print("\nMean over seeds:")
for src in sorted({r["label_source"] for r in rows}):
    for name in sorted({r["model"] for r in rows if r["label_source"] == src}):
        rs = [r for r in rows if r["label_source"] == src and r["model"] == name]
        print(f"{src:5s} {name:16s} n={len(rs)} " + " ".join(
            f"{k}={st.mean(r[k] for r in rs):.3f}" for k in ["F1", "precision", "recall_TPR", "FPR"]))
print(f"\nSaved {a.out}")
