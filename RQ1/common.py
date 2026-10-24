import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET_DIR = ROOT / "dataset"
OUT_DIR = ROOT / "outputs"
TRAIN_FILES = {
    "qwen": DATASET_DIR / "q-fine-tune.jsonl",
}
EVAL_FILE = DATASET_DIR / "m_3000.jsonl"

MODELS = [
    ("bert-base-uncased",                    "BERT-base"),
    ("distilbert-base-uncased",              "DistilBERT"),
    ("albert-base-v2",                       "ALBERT-base"),
    ("huawei-noah/TinyBERT_General_4L_312D", "TinyBERT"),
    ("google/electra-small-discriminator",   "ELECTRA-small"),
    ("google/electra-base-discriminator",    "ELECTRA-base"),
    ("microsoft/codebert-base",              "CodeBERT"),
    ("huggingface/CodeBERTa-small-v1",       "CodeBERTa-small"),
    ("microsoft/graphcodebert-base",         "GraphCodeBERT"),
    ("distilroberta-base",                   "DistilRoBERTa"),
]
SEEDS = [42, 123, 456]
MAX_LENGTH = 512

def load_eval_set(path=EVAL_FILE):
    texts, labels = [], []
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            texts.append(r["text"])
            labels.append(int(r["label"]))
    return texts, labels

def binary_metrics(labels, preds):
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "F1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "precision": prec, "recall_TPR": rec,
        "FPR": fp / (fp + tn) if fp + tn else 0.0,
        "TNR": tn / (fp + tn) if fp + tn else 0.0,
        "FNR": fn / (tp + fn) if tp + fn else 0.0,
        "accuracy": (tp + tn) / len(labels),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn, "flagged": tp + fp,
    }
