#!/usr/bin/env python3
"""Fine-tune a small T5 on the pairs from prepare_data.py.

Usage: train.py <pairs.json> <base model> <output dir> <epochs> <batch size>
The published model: google/t5-efficient-tiny, 6 epochs, batch size 48.
"""

import json
import os
import sys
import time

import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, get_cosine_schedule_with_warmup

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vulnamer as V

pairs, base, out, epochs, bs = (
    sys.argv[1],
    sys.argv[2],
    sys.argv[3],
    int(sys.argv[4]),
    int(sys.argv[5]),
)
rows = json.load(open(pairs))
PRE = "name: "
tr = [r for r in rows if r["split"] == "train"]
va = [r for r in rows if r["split"] == "val"][:1200]
tok = AutoTokenizer.from_pretrained(base)
m = AutoModelForSeq2SeqLM.from_pretrained(base).cuda()
print(base, "params", sum(p.numel() for p in m.parameters()) / 1e6, "M", flush=True)


def coll(b):
    x = tok(
        [PRE + r["text"] for r in b],
        max_length=128,
        truncation=True,
        padding=True,
        return_tensors="pt",
    )
    y = tok(
        text_target=[r["target"] for r in b],
        max_length=32,
        truncation=True,
        padding=True,
        return_tensors="pt",
    ).input_ids
    y[y == tok.pad_token_id] = -100
    x["labels"] = y
    return x


dl = DataLoader(tr, batch_size=bs, shuffle=True, collate_fn=coll, num_workers=2, drop_last=True)
opt = torch.optim.AdamW(m.parameters(), lr=8e-4 if "tiny" in base else 3e-4, weight_decay=0.01)
T = len(dl) * epochs
sch = get_cosine_schedule_with_warmup(opt, 300, T)


def f1(a, b):
    a, b = set(V._tokens(a.lower())), set(V._tokens(b.lower()))
    o = len(a & b)
    return 0 if not o else 2 * o / (len(a) + len(b))


@torch.no_grad()
def ev():
    m.eval()
    s = 0
    for i in range(0, len(va), 64):
        b = va[i : i + 64]
        x = tok(
            [PRE + r["text"] for r in b],
            max_length=128,
            truncation=True,
            padding=True,
            return_tensors="pt",
        ).to("cuda")
        o = m.generate(**x, max_new_tokens=32, num_beams=1)
        t = tok.batch_decode(o, skip_special_tokens=True)
        s += sum(f1(p, r["target"]) for p, r in zip(t, b))
    m.train()
    return s / len(va)


step = 0
t0 = time.time()
best = 0
m.train()
for e in range(epochs):
    for b in dl:
        b = {k: v.cuda() for k, v in b.items()}
        loss = m(**b).loss
        if not torch.isfinite(loss):
            print("NAN", step, flush=True)
            sys.exit(1)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(m.parameters(), 1.0)
        opt.step()
        sch.step()
        opt.zero_grad(set_to_none=True)
        step += 1
        if step % 500 == 0:
            print(
                f"step {step}/{T} loss {loss.item():.3f} {step/(time.time()-t0):.1f} it/s",
                flush=True,
            )
    f = ev()
    print(f"EPOCH {e+1} val_f1 {f:.4f} t={time.time()-t0:.0f}s", flush=True)
    if f > best:
        best = f
        m.save_pretrained(out)
        tok.save_pretrained(out)
print("DONE", best, flush=True)
