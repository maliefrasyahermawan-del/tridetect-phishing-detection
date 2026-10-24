#!/usr/bin/env python3
"""
Fine-tune IndoBERT on synthetic smishing dataset.
Usage: python scripts/train_smishing.py [--epochs=3] [--batch-size=16]
"""

import argparse
import json
from pathlib import Path

import pandas as pd

DATA_PATH = Path(__file__).parent.parent / "tridetect" / "data" / "sms_synthetic.csv"
MODEL_OUT = Path(__file__).parent.parent / "models_pretrained" / "smishing_indobert"
BASE_MODEL = "indolem/indobert-base-uncased"


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--max-len", type=int, default=128)
    p.add_argument("--lr", type=float, default=2e-5)
    return p.parse_args()


def main():
    args = parse_args()

    try:
        import torch
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
        from datasets import Dataset
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install: pip install transformers datasets scikit-learn torch")
        return

    if not DATA_PATH.exists():
        print(f"Dataset not found: {DATA_PATH}")
        print("Run: python scripts/generate_synthetic_sms.py")
        return

    print(f"Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH)
    df["label_id"] = (df["label"] == "smishing").astype(int)

    train_df, val_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label_id"])
    print(f"Train: {len(train_df)} | Val: {len(val_df)}")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_len, padding="max_length")

    train_ds = Dataset.from_pandas(train_df[["text", "label_id"]].rename(columns={"label_id": "labels"}))
    val_ds = Dataset.from_pandas(val_df[["text", "label_id"]].rename(columns={"label_id": "labels"}))
    train_ds = train_ds.map(tokenize, batched=True)
    val_ds = val_ds.map(tokenize, batched=True)
    train_ds.set_format("torch", columns=["input_ids", "attention_mask", "labels"])
    val_ds.set_format("torch", columns=["input_ids", "attention_mask", "labels"])

    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)

    MODEL_OUT.mkdir(parents=True, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=str(MODEL_OUT),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=50,
        fp16=torch.cuda.is_available(),
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
    )

    print(f"\nFine-tuning {BASE_MODEL} for {args.epochs} epoch(s) ...")
    trainer.train()

    model.save_pretrained(MODEL_OUT)
    tokenizer.save_pretrained(MODEL_OUT)

    label_map = {"0": "benign", "1": "smishing"}
    with open(MODEL_OUT / "label_map.json", "w") as f:
        json.dump(label_map, f)

    print(f"\nModel saved to {MODEL_OUT}")
    print("\nEvaluation on validation set:")
    preds = trainer.predict(val_ds)
    import numpy as np
    pred_labels = np.argmax(preds.predictions, axis=1)
    print(classification_report(val_df["label_id"].values, pred_labels, target_names=["benign", "smishing"]))


if __name__ == "__main__":
    main()
