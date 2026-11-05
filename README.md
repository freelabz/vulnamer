# vulnamer

Turns a CVE into a short, human-readable name, using a single Python file and a 33 MB
open-source model.

```text
CVE-2021-44228  Log4Shell - Apache Log4j2 Remote Code Injection
CVE-2026-109618 PHP2Shell - PHP Memory Corruption
CVE-1999-0001   BSD-derived TCP/IP implementations - Denial of Service
```

`vulnamer.py` needs only the standard library. It imports nothing from any other
project, so you can install it or copy the file into yours.

## Install

```bash
pip install vulnamer            # names from the dataset or your own data
pip install "vulnamer[model]"   # also run the model
uv add vulnamer                 # in a uv project
uv tool install vulnamer        # just the CLI
```

The `model` extra needs a Python version that `onnxruntime` publishes wheels for. It may
not be available yet on the newest Python release. The base package has no such limit.

## Three ways to use it

**Use the dataset.** This is the simplest option and needs no ML dependencies. The
dataset is one JSON object per line, rebuilt nightly and published at
`vulnamer.DATASET_URL`:

```json
{"id": "CVE-2021-44228", "name": "Apache Log4j2 Remote Code Injection", "source": "nuclei", "public_name": "Log4Shell", "description_hash": "e7461d0e2a07a711"}
```

```python
import vulnamer

names = vulnamer.read_dataset("vuln_names.jsonl.gz")
print(names["CVE-2021-44228"]["public_name"])  # Log4Shell
```

**Resolve from your own data.** Every argument is optional:

```python
from vulnamer import resolve_name

result = resolve_name(
    description="Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features ...",
    cve_id="CVE-2021-44228",
    nuclei_name="Apache Log4j2 Remote Code Injection",
)
print(result.name, result.source, result.public_name)
```

**Run the model.** Install the `model` extra, download the model from the
[`model-v1` release](https://github.com/freelabz/vulnamer/releases/tag/model-v1) and pass
its directory:

```bash
vulnamer name "SQL injection in the login form of AcmeShop 2.1." --model ./model
```

## How a name is chosen

Sources are tried in this order, and the first good name wins:

| Tier | Source |
|---|---|
| `nuclei` | Nuclei template name |
| `kev` | CISA KEV vulnerability name |
| `ghsa` | GitHub-reviewed advisory summary |
| `cna` | Title from the CVE record |
| `vendor` | `aka '...'` title in the description |
| `kernel` | Subject of the Linux commit message |
| `model` | Generated from the description, then checked |
| `heuristic` | Regular expressions |

Curated names are normalized and quality-gated, so a poor one falls through to the next
tier. If nothing passes, the name is empty.

## Community names

Names like Log4Shell are kept in a separate `public_name` field. They are labels and do
not describe the flaw, so the model is never asked to produce them. They come from:

1. `PUBLIC_NAMES`, a reviewed table in `vulnamer.py`, which always wins.
2. Mining [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) repository names. A
   name needs at least 5 independent owners, at least 20% of a CVE's repositories, at most
   6 CVEs, a coined spelling, and must not be a product named in the description.

Mining favours missing a name over inventing one. To add a name, open a pull request
against the table with a source.

## Building the dataset

```bash
vulnamer build vuln_names.jsonl.gz --model ./model --previous old.jsonl.gz
```

This downloads the sources and names every published CVE. With `--previous`, the model
only runs for CVEs that have no reusable output. Reused names still pass through the
current guard. Without `--previous`, a full run takes hours on CPU.

## Development

```bash
python -m unittest discover tests
VULNAMER_MODEL=./model python -m unittest discover tests  # also tests the real model
```

`training/` holds the scripts that produced the model. See [MODEL_CARD.md](MODEL_CARD.md)
for evaluation, limitations and data licences.

## Releases

Versions follow [Semantic Versioning](https://semver.org/) and are managed by
[release-please](https://github.com/googleapis/release-please). Use
[conventional commits](https://www.conventionalcommits.org/): `fix:` makes a patch
release and `feat:` a minor one. Merging the release pull request tags `vX.Y.Z`, which
publishes to PyPI.

## Attribution

The dataset contains text from the
[GitHub Advisory Database](https://github.com/github/advisory-database) (CC-BY-4.0), and
from nuclei-templates (MIT), CISA KEV (CC0) and the CVE List
([Terms of Use](https://www.cve.org/Legal/TermsOfUse)).

The code is under the MIT licence.
