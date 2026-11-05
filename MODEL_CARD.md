# Model card: vulnamer tiny

Turns a CVE description into a short name such as `Apache Struts - Code Execution`.
It is a fallback, used only when no curated name exists.

| | |
|---|---|
| Base model | [`google/t5-efficient-tiny`](https://huggingface.co/google/t5-efficient-tiny) (Apache-2.0) |
| Parameters | 15.6M |
| Format | int8-quantized ONNX: encoder 11.2 MB, decoder 20.4 MB, tokenizer 2.4 MB |
| Decoding | Greedy, at most 32 new tokens, source truncated to 128 tokens |
| Runtime | `onnxruntime`, `tokenizers`, `numpy`. CPU only. |
| Speed | 24.5 descriptions/s on 4 CPU threads of a Ryzen 7 5800H that was also busy with GPU training |

## Training

The model was fine-tuned for 6 epochs with batch size 48 on an RTX 3050 4 GB, in about
34 minutes. See `training/`.

The labels are human-written titles from nuclei, CISA KEV, GitHub Security Advisories
and CVE List CNA titles. 25,000 old CVEs without a title got weak labels from the
heuristic instead. Splits are by product, so test products were never seen in training:

| Split | Pairs |
|---|---|
| Train | 114,835 |
| Validation | 2,602 |
| Test | 4,530 |

The published model was trained on NVD descriptions. `training/prepare_data.py` reads
CVE List descriptions instead, so retraining with it will not exactly reproduce this
model.

## Evaluation

Token F1 against the human title, on the test set of unseen products:

| Approach | F1 | Named |
|---|---|---|
| Heuristic only | 0.212 | 43.5% |
| Raw model | 0.645 | 100% |
| Model behind the output guard, heuristic fallback | 0.619 | 94.4% |
| Names accepted by the guard | 0.667 | 90.9% |

0.87% of accepted names state a flaw that conflicts with the human title.

Token F1 only approximates quality. A correct name worded differently scores low.

## Output guard

Model output is only used if `check_generated_name` accepts it. It requires product words
to appear in the description, rejects flaws that contradict the description, and rejects
cut-off output and repetition loops. A rejected name falls back to the heuristic or to no
name at all, which is preferred to a wrong name.

## Limitations

- Names can still be wrong. The guard catches unsupported products and contradictory
  flaws, not every mistake, and descriptions that state no flaw cannot be checked.
- The model works from the description alone, so a vague description gives a vague name.
- Long product lists can be cut off or dropped.
- CVEs from the same product can get identical names.
- No larger model was compared. A FLAN-T5-small run ran out of memory, and its rerun was
  stopped because the tiny model met the size goal.
- It does not generate community names such as Log4Shell. See the README.
- Measured on English descriptions only.

## Licences

The model is derived from an Apache-2.0 base model. Training data:

| Source | Licence |
|---|---|
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | CC-BY-4.0 |
| [CVE List](https://github.com/CVEProject/cvelistV5) | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| [NVD](https://nvd.nist.gov/) | Public domain, not endorsed by NIST |
