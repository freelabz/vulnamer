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

**Run the model.** Install the `model` extra. The first call downloads the
[`model-v1` release](https://github.com/freelabz/vulnamer/releases/tag/model-v1), checks its
SHA-256 and caches it:

```python
from vulnamer import ModelNamer, resolve_name

namer = ModelNamer.load()  # ModelNamer.load(download=False) never touches the network
print(resolve_name("SQL injection in the login form of AcmeShop 2.1.", namer=namer).name)
```

From the command line, see [Command line](#command-line).

The same description always gives the same name. The model runs one description at a time,
because its int8 quantization would otherwise let a name depend on the rest of a batch.

**Look names up.** `lookup_name("CVE-2026-109618")` downloads the nightly dataset on first
use, caches it under `$XDG_CACHE_HOME/vulnamer` and refreshes it once it is a day old.
`lookup_name(..., offline=True)` only reads the cache. `NAMES_URL` points to a smaller,
names-only dataset with the fields `id`, `name` and `public_name`, for when you don't need
the source of each name. `DATASET_URL` points to the full one. Both are gzipped JSON lines,
and `read_dataset` reads either.

## Command line

`vulnamer name` looks a CVE up in the nightly dataset:

```console
$ vulnamer name CVE-2026-109618
{"name": "PHP Memory Corruption", "source": "kev", "public_name": "PHP2Shell"}
```

Give a description too, and it is named when the CVE is not in the dataset yet. Add
`--model` to run the published model on it, or `--model ./model` for a local copy:

```bash
vulnamer name CVE-2026-999999 -d "SQL injection in the login form of AcmeShop 2.1." --model
vulnamer name -d "SQL injection in the login form of AcmeShop 2.1."   # no lookup
```

`-v` prints each step on stderr, so you can see which sources were checked and why each
one was used or skipped. `--offline` only uses cached files.

```console
$ vulnamer name CVE-2099-0001 -d "SQL injection in the login form of AcmeShop 2.1." -v
[vulnamer] dataset: using cached ~/.cache/vulnamer/vuln_names.jsonl.gz (2.3 hours old)
[vulnamer] dataset: CVE-2099-0001 is not listed
[vulnamer] dataset: no name for CVE-2099-0001, naming the description instead
[vulnamer] nuclei, kev, ghsa, cna: no titles given, the nightly dataset has them by CVE ID
[vulnamer] vendor: no usable 'aka' title in the description
[vulnamer] kernel: not a usable Linux kernel commit message
[vulnamer] model: not used, no model loaded
[vulnamer] heuristic: accepted 'login form of AcmeShop - SQL Injection'
```

When the dataset has the CVE, the log says which source named it. The other sources were
checked when the dataset was built.

When nothing can be named, the JSON still prints with `null` fields, and a line on stderr
says what would help:

```console
$ vulnamer name -d "Shell injection on Command Error"
{"name": null, "source": null, "public_name": null}
vulnamer: no name found. Pass a CVE ID to use the nightly dataset. Install "vulnamer[model]" and add --model to run the model on the description.
```

In Python, the same messages go to the `vulnamer` logger at `DEBUG` level:

```python
import logging

logging.basicConfig()
logging.getLogger("vulnamer").setLevel(logging.DEBUG)
```

`vulnamer download-model [DIR]` fetches the model ahead of time.

### One source at a time

`--source` skips the dataset and asks sources live, so you can see what each one gives.
It takes `all` or a comma-separated list of `nuclei`, `kev`, `ghsa`, `cna`, `vendor`,
`kernel`, `model` and `heuristic`:

```console
$ vulnamer name CVE-2021-44228 --source kev
{"id": "CVE-2021-44228", "name": "Apache Log4j2 Remote Code Execution", "source": "kev", "public_name": "Log4Shell", "sources": {"kev": {"raw": "Apache Log4j2 Remote Code Execution Vulnerability", "name": "Apache Log4j2 Remote Code Execution"}}}
```

For each source, `raw` is its text, `name` is what survives the checks, and `note` says
why there is no name. The top-level `name` and `source` come from the first named source
in the usual order, so `--source all` reproduces the dataset's choice from today's data.

Only the feeds the chosen sources need are downloaded:

| Source | Live data |
|---|---|
| `nuclei` | nuclei-templates `cves.json` |
| `kev` | the CISA KEV feed |
| `ghsa` | the GitHub advisory API, reviewed advisories only. Set `GITHUB_TOKEN` to lift the limit of 60 calls an hour. |
| `cna` | the CVE record from `cveawg.mitre.org` |
| `vendor`, `kernel`, `heuristic`, `model` | the description from the CVE record, or `-d` |

`model` needs the `model` extra. With `-d` and no CVE ID, only the description sources can
answer. `public_name` comes from the reviewed table only. Names mined from PoC-in-GitHub are
in the dataset.

The same in Python:

```python
import vulnamer

evidence, errors = vulnamer.fetch_evidence("CVE-2021-44228", ["kev"])  # errors: feeds that failed
results = vulnamer.name_each_source(sources=["kev"], **evidence)
print(results["kev"].name)  # Apache Log4j2 Remote Code Execution
```

`name_each_source` makes no network calls, so you can pass it titles from your own data.
Pass `namer=vulnamer.ModelNamer.load()` to include the model.

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
