#!/bin/bash
set -e
cd "$(dirname "$0")"
python 01_finetune.py
python 02_eval_models.py
python 03_trufflehog.py
