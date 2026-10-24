# Artifacts
## RQ1: Fine-tuning

- `01_finetune.py`: fine-tunes the compact encoders on `dataset/q-fine-tune.jsonl`
- `02_eval_models.py`: evaluates the fine-tuned models on `dataset/m_3000.jsonl`
- `03_trufflehog.py`: runs TruffleHog on the same evaluation prompts
- `common.py`, `run_all.sh`, `requirements.txt`: shared helpers, full run, dependencies
- `dataset/`: `q-fine-tune.jsonl` (training, validation and test split) and `m_3000.jsonl` (evaluation set)
- `prompt-improvisation/`: `q_200.jsonl` and the zero-shot classification prompt

## RQ2: Mined patterns and spans

- `regexes.json`: the mined regular expressions
- `spans.jsonl`: the mined sensitive spans
- `m_span_616.jsonl`: the annotated spans for the sensitive evaluation prompts

## RQ3: Sanitization study
- `run_eval.py`, `self_executable_code_repair_dataset.json`: the code-repair evaluation (needs a local Ollama server)

