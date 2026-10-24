import argparse, json, random, shutil, tempfile
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from torch.utils.data import Dataset
from transformers import (AutoModelForSequenceClassification, AutoTokenizer, Trainer,
                          TrainingArguments, set_seed)

from common import MAX_LENGTH, MODELS, OUT_DIR, SEEDS, TRAIN_FILES

BATCH_SIZE, EPOCHS, LR, WARMUP_STEPS, WEIGHT_DECAY = 16, 3, 2e-5, 100, 0.01

def prepare_data(path):
    splits = {"train": [], "val": [], "test": []}
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            splits[r["split"]].append({"text": r["text"], "label": int(r["label"])})
    print(f"[data] train={len(splits['train'])} val={len(splits['val'])} test={len(splits['test'])}")
    return splits["train"], splits["val"], splits["test"]

class PromptDataset(Dataset):
    def __init__(self, records, tokenizer):
        self.labels = [r["label"] for r in records]
        self.enc = tokenizer([r["text"] for r in records], truncation=True, padding="max_length",
                             max_length=MAX_LENGTH, return_tensors="pt")

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, i):
        item = {k: v[i] for k, v in self.enc.items() if k in ("input_ids", "attention_mask", "token_type_ids")}
        item["labels"] = torch.tensor(self.labels[i], dtype=torch.long)
        return item

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    p, r, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
    return {"accuracy": accuracy_score(labels, preds), "f1": f1, "precision": p, "recall": r}

def run_single(model_id, name, seed, data, save_dir):
    train, val, test = data
    set_seed(seed)
    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, num_labels=2, ignore_mismatched_sizes=True)
    with tempfile.TemporaryDirectory(prefix="ft_") as tmp:
        args = TrainingArguments(
            output_dir=tmp, num_train_epochs=EPOCHS, per_device_train_batch_size=BATCH_SIZE,
            per_device_eval_batch_size=BATCH_SIZE, learning_rate=LR, warmup_steps=WARMUP_STEPS,
            weight_decay=WEIGHT_DECAY, eval_strategy="epoch", save_strategy="epoch", save_total_limit=1,
            load_best_model_at_end=True, metric_for_best_model="f1", greater_is_better=True,
            logging_steps=50, fp16=torch.cuda.is_available(), dataloader_num_workers=2, report_to="none")
        trainer = Trainer(model=model, args=args, train_dataset=PromptDataset(train, tok),
                          eval_dataset=PromptDataset(val, tok), compute_metrics=compute_metrics)
        trainer.train()
        save_dir.mkdir(parents=True, exist_ok=True)
        trainer.save_model(str(save_dir))
        tok.save_pretrained(str(save_dir))
        res = trainer.evaluate(PromptDataset(test, tok))
    del model, trainer
    torch.cuda.empty_cache()
    return {"model": name, "seed": seed, "test_accuracy": res["eval_accuracy"], "test_f1": res["eval_f1"],
            "test_precision": res["eval_precision"], "test_recall": res["eval_recall"]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label-source", choices=list(TRAIN_FILES), default="qwen")
    ap.add_argument("--models", nargs="*", help="short names, e.g. GraphCodeBERT (default: all 10)")
    ap.add_argument("--seeds", nargs="*", type=int, default=SEEDS)
    ap.add_argument("--models-dir", default=str(OUT_DIR / "models"))
    ap.add_argument("--results-dir", default=str(OUT_DIR / "results"))
    ap.add_argument("--train-file", help="override the labeled dataset path")
    a = ap.parse_args()

    models = [m for m in MODELS if not a.models or m[1] in a.models]
    data = prepare_data(a.train_file or TRAIN_FILES[a.label_source])
    out_json = Path(a.results_dir) / f"finetune_{a.label_source}.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    results = json.load(open(out_json)) if out_json.exists() else []
    done = {(r["model"], r["seed"]) for r in results}

    for model_id, name in models:
        for seed in a.seeds:
            save_dir = Path(a.models_dir) / a.label_source / name / f"seed_{seed}"
            if (name, seed) in done and (save_dir / "model.safetensors").exists():
                print(f"skip {name} seed {seed} (already done)")
                continue
            print(f"\n=== {a.label_source} | {name} | seed {seed} ===")
            r = run_single(model_id, name, seed, data, save_dir)
            results = [x for x in results if (x["model"], x["seed"]) != (name, seed)] + [r]
            json.dump(results, open(out_json, "w"), indent=2)
            print(f"test F1 = {r['test_f1']:.4f}")

if __name__ == "__main__":
    main()
