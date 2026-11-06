#!/usr/bin/env python3
"""vulnamer: turn a CVE into a short, human-readable vulnerability name.

A single, dependency-free module. Names are resolved from the best available
evidence, in order:

    nuclei > kev > ghsa > cna > vendor ("aka" titles) > kernel > model > heuristic

Curated names are normalized and quality-gated, so a poor one falls through to
the next tier rather than being shown. The optional model tier needs
``onnxruntime`` and ``tokenizers``; everything else is standard library.

Community names ("Log4Shell", "PHP2Shell") are a label rather than a
description, so they are returned separately as ``VulnName.public_name``.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

try:
    __version__ = version("vulnamer")
except PackageNotFoundError:  # the file was copied rather than installed
    __version__ = "0.0.0+unknown"

DATASET_URL = "https://github.com/freelabz/vulnamer/releases/download/dataset/vuln_names.jsonl.gz"
NAMES_URL = "https://github.com/freelabz/vulnamer/releases/download/dataset/vuln_names.min.jsonl.gz"
MODEL_VERSION = "model-v1"
MODEL_URL = f"https://github.com/freelabz/vulnamer/releases/download/{MODEL_VERSION}/vulnamer-model.tar.gz"
MODEL_SHA256 = "e3fed2d680bad13454020b66da624ac0e7c753d53cae6bc8cd376a69595573c2"
MODEL_FILES = ("encoder_model.onnx", "decoder_model.onnx", "tokenizer.json")

NUCLEI_CVES_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVELIST_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
GHSA_TARBALL_URL = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main"
POC_TARBALL_URL = "https://codeload.github.com/nomi-sec/PoC-in-GitHub/tar.gz/refs/heads/master"
HTTP_TIMEOUT = 120

MIN_NAME_LENGTH = 12
MAX_NAME_LENGTH = 110
MIN_VENDOR_NAME_WORDS = 3

# Words describing the flaw rather than the affected product.
VULN_WORDS = frozenset("""
    a about access account accounts administrator admin after allows an and arbitrary as at attack
    attacks authenticated authentication authorization before bad based blind bof broken buffer bug
    bypass by cache check client code command commands component condition config configuration
    control corruption credential credentials cross crash csrf data default denial deserialization
    directory disclosure dll dom dos double error escalation execution exhaustion exposed exposure
    external file files flaw flaws for forgery format free from function global handling hardcoded header
    heap hijacking idor improper in inclusion incorrect information injection input insecure
    insufficient integer interface invalid issue issues it key lack leak leakage lfi lpe local
    logic loop malicious memory missing multiple null object of on open oob oom or out overflow
    parameter password path permission permissions plugin plaintext pointer pollution potential
    pre privilege privileges race read redirect reference reflected remote request resource rce
    rfi scripting security sensitive server service session shell site smuggling spoofing sql sqli
    ssrf ssti stack stale state stored string takeover template the theme through to token
    traversal type unauthenticated unauthorized uncontrolled underflow unrestricted unsafe
    untrusted update upload url use user users validation via violation vulnerabilities
    vulnerability vulnerable weak when with write xpath xss xxe zero
    """.split())

_WS_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")
_CVE_RE = re.compile(r"\(?\bCVE-\d{4}-\d{4,}\b(?:\s*[/,&]\s*CVE-\d{4}-\d{4,})*\)?", re.I)
_CWE_SUFFIX_RE = re.compile(r"\s*\(CWE-\d+\)\s*$", re.I)
_TRAILING_VULN_RE = re.compile(r"[\s:,-]*\bvulnerabilit(?:y|ies)\b[\s.]*$", re.I)
_COMMIT_SUBJECT_RE = re.compile(r"^[a-z0-9_]+(?:[/.-][a-z0-9_]+)*(?:\s*,\s*[a-z0-9_/.-]+)*:\s")
_COMMIT_VERB_RE = re.compile(
    r"^(?:fix|fixes|fixed|reject|add|remove|revert|avoid|prevent|handle|ensure|correct|"
    r"validate|do not|don't|drop|make|move|return|skip|use (?!after)|update)\b",
    re.I,
)
_REJECT_RE = re.compile(
    r"(?i)\b(?:security (?:hardening )?(?:release|update|advisory|bulletin|patch)|"
    r"multiple (?:security )?(?:vulnerabilities|issues|flaws)|"
    r"(?:cumulative|critical patch) update|see (?:the )?advisory|"
    r"version check)\b|\b(?:detect(?:ion|or)?|fingerprint(?:ing)?|scanner)\s*$"
)
# Vendors that descriptions leave out, and the products that imply them.
_IMPLIED_WORDS = (
    (re.compile(r"\bGoogle Chrome\b"), "chromium"),
    (
        re.compile(r"\b(?:iOS|iPadOS|macOS|OS X|tvOS|watchOS|visionOS|Safari|iTunes|Xcode)\b"),
        "apple",
    ),
)
_PRODUCT_OF_RE = re.compile(r"\s+(?:product|component) of\b.*?(?=\s+-\s|$)", re.I)
_WORD_LOOP_RE = re.compile(r"(?i)(?<!\S)(\S+)(?:\s+\1(?!\S)){2,}")
_DOUBLED_WORD_RE = re.compile(r"(?i)(?<!\S)(\S+)\s+\1(?!\S)")
# A name that ends here was cut off by the model's length limit.
_CUT_OFF_RE = re.compile(
    r"(?i)\b(?:a|allows?|an|and|are|at|be|by|can|for|from|in|is|multiple|of|on|or|that|the|to|"
    r"via|when|which|with)$"
)
_VENDOR_AKA_RE = re.compile(r"""\baka\s+['"“‘]([^'"”’]{12,120})['"”’]""")

# Version expressions, dropped from generated names: a model should not state them.
_VERSION_RE = re.compile(
    r"(?i)(?:\s*(?:<=?|>=?|≤|≥|before|prior to|through|up to|versions?)\s*)?"
    r"\s*\bv?\d+(?:\.\d+)+[\w.-]*(?:\s*(?:-|to|and|/|through|<=?)\s*v?\d+(?:\.\d+)*[\w.-]*)*"
)


def _collapse(text: str) -> str:
    return _WS_RE.sub(" ", text or "").strip()


def _tokens(text: str) -> List[str]:
    return [token.strip(".-_+") for token in _TOKEN_RE.findall(text or "")]


def _alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _known_text(description: str) -> str:
    """Squash a description for word lookups, adding vendors its products imply."""
    implied = [word for pattern, word in _IMPLIED_WORDS if pattern.search(description)]
    return _alnum(description) + " " + " ".join(implied)


def shorten_name(name: str, limit: int = MAX_NAME_LENGTH) -> str:
    """Trim a long name at a clause boundary, keeping the product and the flaw."""
    if len(name) <= limit:
        return name
    best = ""
    for separator in (" — ", " – ", ": ", " via ", " leading to ", " in "):
        position = name.rfind(separator, 0, limit)
        if position >= MIN_NAME_LENGTH and position > len(best):
            best = name[:position]
    return best.strip(" -:;,.") or name


def normalize_name(raw: Optional[str]) -> str:
    """Tidy a raw title into ``Product - Flaw`` style, without judging its quality."""
    name = _collapse(raw or "")
    name = _CVE_RE.sub("", name)
    name = _CWE_SUFFIX_RE.sub("", name)
    name = re.sub(r"\s*\|\s*", " - ", name)
    name = re.sub(r"\s*\(\s*\)\s*", " ", name)
    name = _TRAILING_VULN_RE.sub("", name)
    return shorten_name(_collapse(name).strip(" -:;,."))


def strip_versions(name: str) -> str:
    """Remove version expressions from a name."""
    stripped = _collapse(_VERSION_RE.sub(" ", name))
    stripped = re.sub(r"\s+-\s+-\s+", " - ", stripped)
    return stripped.strip(" -:;,.")


def _is_commit_subject(name: str) -> bool:
    prefix = _COMMIT_SUBJECT_RE.match(name)
    if prefix:
        return "/" in prefix.group(0) or bool(_COMMIT_VERB_RE.match(name[prefix.end() :]))
    return bool(_COMMIT_VERB_RE.match(name))


def is_good_name(name: str, description: str = "") -> bool:
    """Tell whether a normalized name identifies both a product and a flaw.

    Pass ``description`` for free-form titles to also require the product to be
    mentioned there. Leave it empty for human-curated sources, which can use a
    product name that the description spells differently.
    """
    if not MIN_NAME_LENGTH <= len(name) <= MAX_NAME_LENGTH:
        return False
    if _is_commit_subject(name):
        return False
    if _REJECT_RE.search(name):
        return False

    product_tokens = [
        token
        for token in _tokens(name)
        if token.lower() not in VULN_WORDS and not token.replace(".", "").isdigit()
    ]
    if not product_tokens:
        return False
    if description:
        known = _known_text(description)
        return any(_alnum(token) in known for token in product_tokens)
    return True


def clean_name(raw: Optional[str], description: str = "") -> Optional[str]:
    """Return a presentable name from a raw title, or None if it is not good enough."""
    name = normalize_name(raw)
    return name if is_good_name(name, description) else None


def vendor_name(description: str) -> Optional[str]:
    """Extract the title some vendors embed in descriptions as ``aka '<title>'``."""
    match = _VENDOR_AKA_RE.search(description or "")
    name = clean_name(match.group(1), description) if match else None
    if not name:
        return None
    # "aka" also introduces plain phrases: "the second issue", "unsigned int[5]",
    # "Keyboard Layout". Vendor titles name a product and a flaw in title case.
    words = name.split()
    if len(words) < MIN_VENDOR_NAME_WORDS or words[0].islower():
        return None
    return name


# Canonical flaw names, most specific first.
_FLAW_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bsql[\s-]*injection|\bsqli\b", "SQL Injection"),
    (r"\bcross[\s-]*site request forgery|\bcsrf\b", "Cross-Site Request Forgery"),
    (r"\bcross[\s-]*site scripting|\bxss\b", "Cross-Site Scripting"),
    (r"\bserver[\s-]*side request forgery|\bssrf\b", "Server-Side Request Forgery"),
    (r"\bserver[\s-]*side template injection|\bssti\b", "Server-Side Template Injection"),
    (r"\bxml external entit|\bxxe\b", "XML External Entity Injection"),
    (r"\bdirectory traversal|\bpath traversal", "Path Traversal"),
    (r"\blocal file inclusion|\blfi\b", "Local File Inclusion"),
    (r"\bremote file inclusion|\brfi\b", "Remote File Inclusion"),
    (
        r"\bcommand injection|execute (?:arbitrary )?(?:os |shell |system )?commands",
        "Command Injection",
    ),
    (r"\bdeserializ", "Insecure Deserialization"),
    (r"\buse[\s-]*after[\s-]*free|\buaf\b", "Use-After-Free"),
    (r"\bdouble free", "Double Free"),
    (r"\bheap[\s-]*(?:based )?(?:buffer )?overflow", "Heap Buffer Overflow"),
    (r"\bstack[\s-]*(?:based )?(?:buffer )?overflow", "Stack Buffer Overflow"),
    (r"\bbuffer over(?:flow|run)", "Buffer Overflow"),
    (r"\binteger (?:over|under)flow", "Integer Overflow"),
    (r"\bformat string", "Format String"),
    (r"\btype confusion", "Type Confusion"),
    (r"\bout[\s-]*of[\s-]*bounds (?:read|access)", "Out-of-Bounds Read"),
    (r"\bout[\s-]*of[\s-]*bounds write", "Out-of-Bounds Write"),
    (r"\bnull pointer", "NULL Pointer Dereference"),
    (r"\brace condition", "Race Condition"),
    (r"\bopen redirect", "Open Redirect"),
    (
        r"\b(?:arbitrary|unrestricted) file upload|upload (?:and execute )?arbitrary",
        "Arbitrary File Upload",
    ),
    (r"\barbitrary file (?:read|download)|read arbitrary files", "Arbitrary File Read"),
    (r"\b(?:authentication bypass|bypass (?:the )?authentication)", "Authentication Bypass"),
    (
        r"\b(?:privilege escalation|elevation of privilege|gain (?:root |elevated |additional )?privileges)",
        "Privilege Escalation",
    ),
    (r"\bhard[\s-]*coded (?:credential|password|key)", "Hardcoded Credentials"),
    (
        r"\b(?:remote code execution|\brce\b|code execution|execute (?:arbitrary )?code)",
        "Code Execution",
    ),
    (r"\b(?:denial[\s-]*of[\s-]*service|\bdos\b|crash)", "Denial of Service"),
    (
        r"\b(?:information (?:disclosure|exposure|leak)|sensitive information|obtain sensitive)",
        "Information Disclosure",
    ),
    (r"\bmemory corruption", "Memory Corruption"),
    (r"\binsufficient policy enforcement", "Insufficient Policy Enforcement"),
    (r"\binappropriate implementation", "Inappropriate Implementation"),
    (r"\blogic (?:issue|error|flaw)", "Logic Flaw"),
)
_FLAWS = tuple((re.compile(pattern, re.I), label) for pattern, label in _FLAW_PATTERNS)

_LEADING_FLAW_RE = re.compile(
    r"^(?:\*\*[^*]*\*\*\s*)?(?:multiple\s+)?[\w\s,/()'-]{0,80}?"
    r"(?:vulnerabilit(?:y|ies)|flaws?|issues?|overflows?|injection|use[\s-]after[\s-]free|double free|"
    r"out[\s-]of[\s-]bounds (?:read|write|memory access)|type confusion|memory corruption|"
    r"policy enforcement|implementation|validation)\s+in\s+(?P<rest>.+)",
    re.I,
)
_PRODUCT_END_RE = re.compile(
    r"\s+(?:v?\d[\w.-]*|allows?|before|prior|through|up to|versions?|via|when|on|could|can|"
    r"may|might|has|have|is|are|does|did|contains?|uses?|for|and earlier|fails?)\b|[,;:(]",
    re.I,
)
_LEADING_PRODUCT_RE = re.compile(
    r"^(?:[Tt]he\s+|[Aa]n?\s+|[Ii]n\s+)?(?P<product>[A-Z0-9][\w.+'/-]*(?:\s+[A-Z0-9][\w.+'/-]*){0,6})"
)
_BARE_FLAW_RE = re.compile(r"(?i)^out[\s-]*of[\s-]*bounds$")
_APPLE_PRODUCT_RE = re.compile(
    r"\b(?:fixed in|prior to)\s+(iOS|iPadOS|macOS|tvOS|watchOS|visionOS|Safari|iTunes|Xcode)\b"
)
# Capitalized sentence openers, which are not products.
_NOT_A_PRODUCT = frozenset("""
    after although an as at because before by certain due during for from if improper in
    incorrect insufficient it missing multiple on once several since some there these this those
    under unspecified upon users when where while with within
    """.split())


_LINUX_KERNEL_PREFIX = "In the Linux kernel, the following vulnerability has been resolved:"
_KERNEL_SUBJECT_RE = re.compile(r"^([\w./-]+(?:\s*:\s*[\w./-]+)?)\s*:\s+(.+)$")
_KERNEL_FLAWS = (
    (re.compile(r"(?i)\bdeadlock"), "Deadlock"),
    (re.compile(r"(?i)\b(?:memory |ref(?:erence|count)? )?leak|memleak"), "Memory Leak"),
    (re.compile(r"(?i)\bwarn(?:ing)?\b|\bbug_on\b"), "Kernel Warning"),
)


def _kernel_flaw(subject: str) -> Optional[str]:
    for pattern, label in _KERNEL_FLAWS:
        if pattern.search(subject):
            return label
    return None


def _flaw_label(description: str) -> Optional[str]:
    for pattern, label in _FLAWS:
        if pattern.search(description):
            return label
    return None


def _product_guess(description: str) -> Optional[str]:
    apple = _APPLE_PRODUCT_RE.search(description)
    if apple:
        return f"Apple {apple.group(1)}"
    head = description
    leading = _LEADING_FLAW_RE.match(description)
    if leading:
        head = _PRODUCT_END_RE.split(leading.group("rest"), maxsplit=1)[0]
        # "in foo.php in Product" names a component first
        head = re.split(r"\s+in\s+(?:the\s+)?", head)[-1]
        head = re.sub(r"^(?:the|an?)\s+", "", head, flags=re.I)
    else:
        match = _LEADING_PRODUCT_RE.match(description)
        if not match:
            return None
        head = _PRODUCT_END_RE.split(match.group("product"), maxsplit=1)[0]
    head = re.sub(
        r"\s+(?:plugin|module|component|function|package)$", "", head.strip(), flags=re.I
    )
    return head if 2 <= len(head) <= 60 else None


def linux_kernel_name(description: str) -> Optional[str]:
    """Name a Linux kernel CVE, whose description is the fixing commit message."""
    text = (description or "").strip()
    if not text.startswith(_LINUX_KERNEL_PREFIX):
        return None
    message = text[len(_LINUX_KERNEL_PREFIX) :].strip()
    # The subject is the commit's first line, or first sentence if newlines were lost.
    subject = message.splitlines()[0] if "\n" in message else re.split(r"\.\s", message)[0]
    match = _KERNEL_SUBJECT_RE.match(_collapse(subject))
    if not match:
        return None
    subsystem, subject = match.group(1), match.group(2).rstrip(".")
    flaw = _flaw_label(subject) or _kernel_flaw(subject)
    if flaw:
        return f"Linux Kernel {subsystem} - {flaw}"
    name = f"Linux Kernel {subsystem}: {subject}"
    return name if len(name) <= MAX_NAME_LENGTH else name[:MAX_NAME_LENGTH].rsplit(" ", 1)[0]


def heuristic_name(description: str, leading_flaw_only: bool = False) -> Optional[str]:
    """Build ``Product - Flaw`` from a description without any model."""
    description = _collapse(description)
    description = re.sub(r"^(?:\*\*[^*]*\*\*\s*)", "", description)
    if leading_flaw_only and not _LEADING_FLAW_RE.match(description):
        return None
    product, flaw = _product_guess(description), _flaw_label(description)
    if not product or not flaw:
        return None
    if product.lower() in VULN_WORDS or not product[0].isalnum():
        return None
    if _flaw_label(product) or _BARE_FLAW_RE.match(product):
        return None
    if product.split()[0].lower() in _NOT_A_PRODUCT:
        return None
    return f"{product} - {flaw}"


_CVE_IN_REPO_RE = re.compile(r"cve[-_]?\d{4}[-_]?\d{4,}", re.I)
_REPO_URL_RE = re.compile(r"github\.com/([^/\s]+)/([^/?#\s]+)", re.I)
_REPO_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]+")
_ANNOTATED_ALIAS_RE = re.compile(
    r"""(?i)\b(?:aka|a\.k\.a\.?|also (?:known|referred to) as|known as|dubbed|nicknamed|called)\b"""
    r"""[\s"'“‘(]*([^\s"'”’),.;]+(?:\s+[^\s"'”’),.;]+)?)"""
)

# Repository-name words that never identify a vulnerability.
_NOT_A_NICKNAME = frozenset("""
    apache advisory analysis android attack audit auth automated backport bypass cisco cloud
    code command demo detect detection detector deserialization docker environment exchange
    execution exp exploit exploitation exploits fix framework github gitlab google guard hack
    hacking injection java kernel lab labs linux local mass microsoft mitigation module nginx
    nuclei oracle overflow patch patched payload poc privesc proof public python remote repro
    reproduce reproduction research root rust scan scanner script security server shell
    simple spring test tester testing tool tools traversal vuln vulnerable vulnerability vulnerabilities
    windows wordpress writeup
    """.split())
MIN_NICKNAME_OWNERS = 5
MIN_NICKNAME_SHARE = 0.2
MAX_NICKNAME_CVES = 6

# "<Product><flaw>" repository names, which look coined but are not names.
_DESCRIPTIVE_SUFFIX_RE = re.compile(
    r"(?:rce|lpe|uaf|ace|cmd|sqli|xss|xxe|ssrf|poc|cve|exploiter?|exp|lab|research|scanner|"
    r"credentials?|privilege|sandbox|docker|checker|ebs)$",
    re.I,
)
# A coined name mixes case or digits, unlike the plain words common in repositories.
_COINED_RE = re.compile(r"^[A-Za-z]*(?:[a-z][A-Z]|[a-zA-Z]\d[a-zA-Z])[A-Za-z0-9]*$")

# Well-established community names, reviewed by hand. Dictionary words such as
# "Meltdown" cannot be told apart from repository noise, so they are listed here.
PUBLIC_NAMES: Dict[str, str] = {
    "CVE-2014-0160": "Heartbleed",
    "CVE-2014-1266": "goto fail",
    "CVE-2014-3566": "POODLE",
    "CVE-2014-3704": "Drupalgeddon",
    "CVE-2014-4114": "Sandworm",
    "CVE-2014-6271": "Shellshock",
    "CVE-2015-0204": "FREAK",
    "CVE-2015-0235": "GHOST",
    "CVE-2015-1538": "Stagefright",
    "CVE-2015-4000": "Logjam",
    "CVE-2016-0800": "DROWN",
    "CVE-2016-3714": "ImageTragick",
    "CVE-2016-5195": "Dirty COW",
    "CVE-2017-0144": "EternalBlue",
    "CVE-2017-1000251": "BlueBorne",
    "CVE-2017-5715": "Spectre",
    "CVE-2017-5753": "Spectre",
    "CVE-2017-5754": "Meltdown",
    "CVE-2018-12130": "ZombieLoad",
    "CVE-2018-3615": "Foreshadow",
    "CVE-2018-7600": "Drupalgeddon2",
    "CVE-2019-0708": "BlueKeep",
    "CVE-2019-7304": "Dirty Sock",
    "CVE-2020-0601": "CurveBall",
    "CVE-2020-0796": "SMBGhost",
    "CVE-2020-10713": "BootHole",
    "CVE-2020-1350": "SIGRed",
    "CVE-2020-1472": "Zerologon",
    "CVE-2020-1938": "Ghostcat",
    "CVE-2021-1675": "PrintNightmare",
    "CVE-2021-26855": "ProxyLogon",
    "CVE-2021-3156": "Baron Samedit",
    "CVE-2021-34473": "ProxyShell",
    "CVE-2021-33909": "Sequoia",
    "CVE-2021-34527": "PrintNightmare",
    "CVE-2021-36934": "HiveNightmare",
    "CVE-2021-36942": "PetitPotam",
    "CVE-2021-38647": "OMIGOD",
    "CVE-2021-4034": "PwnKit",
    "CVE-2021-42278": "noPac",
    "CVE-2021-42287": "noPac",
    "CVE-2021-44228": "Log4Shell",
    "CVE-2022-0847": "Dirty Pipe",
    "CVE-2022-22965": "Spring4Shell",
    "CVE-2022-30190": "Follina",
    "CVE-2022-3602": "SpookySSL",
    "CVE-2022-3786": "SpookySSL",
    "CVE-2022-40982": "Downfall",
    "CVE-2022-42889": "Text4Shell",
    "CVE-2023-20593": "Zenbleed",
    "CVE-2023-23583": "Reptar",
    "CVE-2023-4911": "Looney Tunables",
    "CVE-2023-44487": "HTTP/2 Rapid Reset",
    "CVE-2023-48795": "Terrapin",
    "CVE-2023-4966": "CitrixBleed",
    "CVE-2024-21413": "MonikerLink",
    "CVE-2024-3094": "XZ Backdoor",
    "CVE-2024-34102": "CosmicSting",
    "CVE-2024-6387": "regreSSHion",
    "CVE-2025-1974": "IngressNightmare",
    "CVE-2025-53770": "ToolShell",
    "CVE-2025-55182": "React2Shell",
    "CVE-2025-5777": "CitrixBleed 2",
    "CVE-2025-8671": "MadeYouReset",
    "CVE-2026-109618": "PHP2Shell",
    "CVE-2026-109619": "PHP2Shell",
}


def _repo_candidates(repository: str) -> Set[str]:
    """Return the words of a repository name, and adjacent pairs joined ("dirty-pipe")."""
    words = _REPO_WORD_RE.findall(_CVE_IN_REPO_RE.sub(" ", repository))
    words = [word for word in words if len(word) >= 2]
    candidates = {word for word in words if len(word) >= 4}
    candidates.update(first + second for first, second in zip(words, words[1:]))
    return candidates


def _pretty_spelling(spellings: Counter) -> str:
    """Pick how to display a nickname, preferring spellings that carry capitals."""
    cased = Counter({word: n for word, n in spellings.items() if word != word.lower()})
    choice = (cased or spellings).most_common(1)[0][0]
    return choice if choice != choice.lower() else choice.capitalize()


def mine_public_names(
    references: Iterable[Tuple[str, str]], descriptions: Dict[str, str]
) -> Dict[str, str]:
    """Find community names ("PHP2Shell") from the GitHub repositories of each CVE.

    A name is kept when several independent owners use it for the same CVE, when
    it accounts for a fair share of that CVE's repositories, when the description
    does not simply use it as the product name, when it is specific to a handful
    of CVEs, and when it is spelled like a coined name. This is deliberately
    strict: new names should be missed rather than invented. ``PUBLIC_NAMES``
    covers established ones.
    """
    owners: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    spellings: Dict[str, Counter] = defaultdict(Counter)
    all_owners: Dict[str, Set[str]] = defaultdict(set)
    for cve_id, url in references:
        match = _REPO_URL_RE.search(url or "")
        if not match:
            continue
        owner, repository = match.group(1).lower(), match.group(2)
        all_owners[cve_id].add(owner)
        for candidate in _repo_candidates(repository):
            key = candidate.lower()
            owners[cve_id][key].add(owner)
            spellings[key][candidate] += 1

    cve_count = Counter(key for by_key in owners.values() for key in by_key)
    names: Dict[str, str] = {}
    for cve_id, by_key in owners.items():
        description = descriptions.get(cve_id, "")
        annotated = {_alnum(found) for found in _ANNOTATED_ALIAS_RE.findall(description)}
        haystack = _alnum(description)
        ranked = sorted(by_key.items(), key=lambda item: (-len(item[1]), len(item[0])))
        for key, key_owners in ranked:
            share = len(key_owners) / len(all_owners[cve_id])
            if len(key_owners) < MIN_NICKNAME_OWNERS:
                break
            if share < MIN_NICKNAME_SHARE:
                continue
            if key in _NOT_A_NICKNAME or key.lower() in VULN_WORDS:
                continue
            if cve_count[key] > MAX_NICKNAME_CVES:
                continue
            if key in haystack and not any(key in alias for alias in annotated):
                continue
            spelling = _pretty_spelling(spellings[key])
            first_word = re.match(r"[A-Z]?[a-z]+|[A-Z]+", spelling).group(0).lower()
            if first_word in _NOT_A_NICKNAME:
                continue
            if _COINED_RE.match(spelling) and not _DESCRIPTIVE_SUFFIX_RE.search(spelling):
                names[cve_id] = spelling
                break
    return names


@dataclass(frozen=True)
class VulnName:
    """A resolved name, the tier it came from, and any community name."""

    name: Optional[str]
    source: Optional[str]
    public_name: Optional[str] = None


# Words a generated name may use without the description containing them.
_FREE_WORDS = VULN_WORDS | frozenset("""
    accessed affected allocation are be bounds bypassed bypasses can cause contributor creation
    critical deletion does elevation escape exfiltration font has improperly insufficiently is lead
    leaks manipulated modification not parsing plain possible product products protected redos reset restriction
    sanitization side subscriber symlink text tokens unbounded unescaped unsanitized unvalidated
    wordpress
    """.split())

# Flaws that describe the same bug from different angles do not contradict each other.
_FLAW_FAMILIES: Tuple[frozenset, ...] = (
    frozenset(
        {
            "Path Traversal",
            "Local File Inclusion",
            "Remote File Inclusion",
            "Arbitrary File Read",
            "Information Disclosure",
        }
    ),
    frozenset(
        {
            "Command Injection",
            "Code Execution",
            "Insecure Deserialization",
            "Arbitrary File Upload",
            "Server-Side Template Injection",
            "Remote File Inclusion",
            "Local File Inclusion",
            "SQL Injection",
        }
    ),
    frozenset(
        {
            "Use-After-Free",
            "Double Free",
            "Heap Buffer Overflow",
            "Stack Buffer Overflow",
            "Buffer Overflow",
            "Integer Overflow",
            "Format String",
            "Type Confusion",
            "Memory Corruption",
            "Out-of-Bounds Read",
            "Out-of-Bounds Write",
            "NULL Pointer Dereference",
            "Race Condition",
            "Code Execution",
            "Denial of Service",
            "Privilege Escalation",
            "Information Disclosure",
        }
    ),
    frozenset(
        {
            "Authentication Bypass",
            "Privilege Escalation",
            "Hardcoded Credentials",
            "Information Disclosure",
        }
    ),
)


def _flaw_labels(text: str) -> Set[str]:
    return {label for pattern, label in _FLAWS if pattern.search(text)}


def _flaws_compatible(named: Set[str], described: Set[str]) -> bool:
    for flaw in named:
        related = {flaw}
        for family in _FLAW_FAMILIES:
            if flaw in family:
                related |= family
        if not related & described:
            return False
    return True


def _looks_broken(name: str) -> bool:
    """Spot typical seq2seq failures: cut-off output and repetition loops."""
    if _CUT_OFF_RE.search(name) or _WORD_LOOP_RE.search(name):
        return True
    tokens = _tokens(name)
    counts = Counter(
        token.lower()
        for token in tokens
        if len(token) >= 4 and not all(part.lower() in _FREE_WORDS for part in token.split("-"))
    )
    if not counts:
        return False
    # restating the product, or three of anything, is a loop
    return counts[tokens[0].lower()] > 1 or max(counts.values()) > 2


def check_generated_name(generated: str, description: str) -> Optional[str]:
    """Accept model output only if the description supports it.

    Every product word must come from the description, a stated flaw must not
    contradict the flaws the description mentions, and the output must not be
    cut off or stuck in a loop.
    """
    name = strip_versions(normalize_name(_PRODUCT_OF_RE.sub("", generated)))
    if _looks_broken(name):
        return None
    name = _DOUBLED_WORD_RE.sub(r"\1", name)
    if not is_good_name(name, description):
        return None
    known = _known_text(description)
    for token in _tokens(name):
        if token.replace(".", "").isdigit() or _alnum(token) in known:
            continue
        if not all(part.lower() in _FREE_WORDS for part in re.split(r"[-_.]", token) if part):
            return None
    described = _flaw_labels(description)
    if described and not _flaws_compatible(_flaw_labels(name), described):
        return None
    return name


class ModelNamer:
    """Name vulnerabilities with an exported ONNX seq2seq model (greedy decoding).

    ``model_dir`` holds ``encoder_model.onnx``, ``decoder_model.onnx`` and
    ``tokenizer.json``. Requires ``onnxruntime`` and ``tokenizers``.
    """

    PREFIX = "name: "
    MAX_SOURCE_TOKENS = 128
    MAX_NEW_TOKENS = 32
    PAD_ID = 0
    EOS_ID = 1

    def __init__(self, model_dir: str, threads: Optional[int] = None):
        import numpy
        import onnxruntime
        from tokenizers import Tokenizer

        options = onnxruntime.SessionOptions()
        if threads:
            options.intra_op_num_threads = threads
        providers = ["CPUExecutionProvider"]
        self._numpy = numpy
        self._encoder = onnxruntime.InferenceSession(
            os.path.join(model_dir, "encoder_model.onnx"), options, providers=providers
        )
        self._decoder = onnxruntime.InferenceSession(
            os.path.join(model_dir, "decoder_model.onnx"), options, providers=providers
        )
        self._tokenizer = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=self.MAX_SOURCE_TOKENS)

    @classmethod
    def load(cls, threads: Optional[int] = None, download: bool = True) -> "ModelNamer":
        """Load the published model from the cache, downloading it if it is missing.

        With ``download=False`` nothing touches the network, and a missing model
        raises an error from ``onnxruntime``.
        """
        return cls(download_model() if download else default_model_dir(), threads)

    def generate(self, descriptions: Sequence[str]) -> List[str]:
        """Return the raw model output for each description.

        Descriptions are always run one at a time. The int8 model scales its input
        from the whole tensor, so batching would make a name depend on its neighbours.
        """
        return [self._generate_one(description) for description in descriptions]

    def _generate_one(self, description: str) -> str:
        numpy = self._numpy
        encoded = self._tokenizer.encode(self.PREFIX + _collapse(description))
        input_ids = numpy.array([encoded.ids], dtype=numpy.int64)
        attention_mask = numpy.array([encoded.attention_mask], dtype=numpy.int64)
        hidden = self._encoder.run(
            None, {"input_ids": input_ids, "attention_mask": attention_mask}
        )[0]

        decoded = [self.PAD_ID]
        for _ in range(self.MAX_NEW_TOKENS):
            logits = self._decoder.run(
                None,
                {
                    "input_ids": numpy.array([decoded], dtype=numpy.int64),
                    "encoder_attention_mask": attention_mask,
                    "encoder_hidden_states": hidden,
                },
            )[0]
            next_id = int(logits[0, -1].argmax())
            if next_id == self.EOS_ID:
                break
            decoded.append(next_id)
        return self._tokenizer.decode(decoded[1:], skip_special_tokens=True)

    def name(self, descriptions: Sequence[str]) -> List[Optional[str]]:
        """Return checked names, with None where the output was not trustworthy."""
        generated = self.generate(descriptions)
        return [check_generated_name(*pair) for pair in zip(generated, descriptions)]


def resolve_name(
    description: str = "",
    cve_id: str = "",
    nuclei_name: Optional[str] = None,
    kev_name: Optional[str] = None,
    ghsa_summary: Optional[str] = None,
    cna_title: Optional[str] = None,
    public_name: Optional[str] = None,
    generated_name: Optional[str] = None,
    namer: Optional[ModelNamer] = None,
) -> VulnName:
    """Resolve the best name from whatever evidence the caller has.

    Every argument is optional. Pass ``generated_name`` for model output that was
    already produced in a batch, or ``namer`` to run the model here.
    """
    public_name = PUBLIC_NAMES.get(cve_id) or public_name
    candidates = (
        ("nuclei", clean_name(nuclei_name)),
        ("kev", clean_name(kev_name)),
        ("ghsa", clean_name(ghsa_summary)),
        ("cna", clean_name(cna_title, description)),
        ("vendor", vendor_name(description)),
        ("kernel", linux_kernel_name(description)),
    )
    for source, name in candidates:
        if name:
            return VulnName(name, source, public_name)

    if generated_name is None and namer is not None and description:
        generated_name = namer.name([description])[0]
    if generated_name:
        return VulnName(generated_name, "model", public_name)

    heuristic = heuristic_name(description)
    if heuristic:
        return VulnName(heuristic, "heuristic", public_name)
    return VulnName(None, None, public_name)


def _http_get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": f"vulnamer/{__version__}"})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:  # nosec B310
        return response.read()


def _download(url: str, directory: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": f"vulnamer/{__version__}"})
    handle, path = tempfile.mkstemp(dir=directory)
    with os.fdopen(handle, "wb") as output:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:  # nosec B310
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    return path
                output.write(chunk)


def parse_nuclei(text: str) -> Dict[str, str]:
    """Parse nuclei-templates' cves.json (JSON lines)."""
    names = {}
    for line in text.splitlines():
        if line.strip():
            entry = json.loads(line)
            name = entry.get("Info", {}).get("Name")
            if name:
                names[entry["ID"]] = name
    return names


def parse_kev(text: str) -> Dict[str, str]:
    """Parse the CISA KEV catalog."""
    catalog = json.loads(text)
    return {
        entry["cveID"]: entry["vulnerabilityName"]
        for entry in catalog.get("vulnerabilities", [])
        if entry.get("vulnerabilityName")
    }


def parse_cve_record(record: dict) -> Optional[Tuple[str, str, str]]:
    """Return (CVE ID, description, CNA title) of a published CVE JSON 5 record."""
    metadata = record.get("cveMetadata", {})
    if metadata.get("state") != "PUBLISHED":
        return None
    cna = record.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    english = [item for item in descriptions if item.get("lang", "").startswith("en")]
    chosen = (english or descriptions or [{}])[0].get("value", "")
    # line breaks stay: they delimit the subject of Linux kernel commit messages
    return metadata["cveId"], chosen.strip(), _collapse(cna.get("title") or "")


def iter_cvelist(path: str) -> Iterator[Tuple[str, str, str]]:
    """Read a cvelistV5 bulk archive, which may be a zip nested in a zip."""
    with zipfile.ZipFile(path) as outer:
        archive = outer
        inner = [name for name in outer.namelist() if name.endswith(".zip")]
        if inner:
            archive = zipfile.ZipFile(io.BytesIO(outer.read(inner[0])))
        for name in archive.namelist():
            if not name.endswith(".json") or "/CVE-" not in name:
                continue
            try:
                parsed = parse_cve_record(json.loads(archive.read(name)))
            except ValueError:
                continue
            if parsed:
                yield parsed


def iter_ghsa_summaries(path: str) -> Iterator[Tuple[str, str]]:
    """Yield (CVE ID, summary) from a tarball of GitHub-reviewed advisories."""
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            if "/github-reviewed/" not in member.name or not member.name.endswith(".json"):
                continue
            extracted = archive.extractfile(member)
            advisory = json.load(extracted) if extracted else {}
            summary = advisory.get("summary")
            if not summary:
                continue
            for alias in advisory.get("aliases", []):
                if alias.startswith("CVE-"):
                    yield alias, summary


def iter_poc_references(path: str) -> Iterator[Tuple[str, str]]:
    """Yield (CVE ID, repository URL) from a tarball of PoC-in-GitHub."""
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            base = os.path.basename(member.name)
            if not base.startswith("CVE-") or not base.endswith(".json"):
                continue
            extracted = archive.extractfile(member)
            for repository in json.load(extracted) if extracted else []:
                url = repository.get("html_url")
                if url:
                    yield base[: -len(".json")], url


def default_model_dir() -> str:
    """Return where the published model is cached."""
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(cache, "vulnamer", MODEL_VERSION)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_model(directory: Optional[str] = None) -> str:
    """Fetch the published model, verify it and return its directory.

    Does nothing if the model is already there. Files appear all at once, so an
    interrupted download or a concurrent process never leaves a partial model.
    """
    target = directory or default_model_dir()
    if all(os.path.isfile(os.path.join(target, name)) for name in MODEL_FILES):
        return target
    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as work_dir:
        archive = _download(MODEL_URL, work_dir)
        checksum = _sha256(archive)
        if checksum != MODEL_SHA256:
            raise ValueError(f"model checksum mismatch: got {checksum}")
        unpacked = os.path.join(work_dir, "model")
        os.mkdir(unpacked)
        with tarfile.open(archive, "r:gz") as tar:
            for name in MODEL_FILES:  # by name, so the archive cannot write anywhere else
                with tar.extractfile(f"./{name}") as source:
                    with open(os.path.join(unpacked, name), "wb") as output:
                        shutil.copyfileobj(source, output)
        try:
            os.replace(unpacked, target)
        except OSError:  # a concurrent process finished first
            if not os.path.isfile(os.path.join(target, MODEL_FILES[0])):
                raise
    return target


def description_hash(description: str) -> str:
    """Identify a description, to reuse earlier model output when it is unchanged."""
    return hashlib.sha256(_collapse(description).encode("utf-8", "replace")).hexdigest()[:16]


def read_dataset(path: str) -> Dict[str, dict]:
    """Load a names dataset (gzipped JSON lines) into a dict keyed by CVE ID."""
    with gzip.open(path, "rt", encoding="utf-8") as lines:
        return {entry["id"]: entry for entry in map(json.loads, lines)}


def names_entry(result: dict) -> Optional[dict]:
    """Reduce a dataset row to what a lookup needs, or None if it has no name at all."""
    if not result.get("name") and not result.get("public_name"):
        return None
    keys = ("id", "name", "public_name")
    return {key: result[key] for key in keys if result.get(key)}


def build_dataset(
    records: Iterable[Tuple[str, str, str]],
    nuclei: Dict[str, str],
    kev: Dict[str, str],
    ghsa: Dict[str, str],
    public_names: Dict[str, str],
    namer: Optional[ModelNamer] = None,
    previous: Optional[Dict[str, dict]] = None,
) -> Iterator[dict]:
    """Resolve names for all records, running the model only where it is needed."""
    previous = previous or {}

    def entry(cve_id, description, title, generated=None):
        resolved = resolve_name(
            description,
            cve_id,
            nuclei.get(cve_id),
            kev.get(cve_id),
            ghsa.get(cve_id),
            title,
            public_names.get(cve_id),
            generated,
        )
        result = {"id": cve_id, "name": resolved.name, "source": resolved.source}
        if resolved.public_name:
            result["public_name"] = resolved.public_name
        result["description_hash"] = description_hash(description)
        return result

    for cve_id, description, title in records:
        result = entry(cve_id, description, title)
        if result["source"] not in (None, "heuristic") or not namer or not description:
            yield result
            continue
        earlier = previous.get(cve_id)
        unchanged = earlier and earlier.get("description_hash") == result["description_hash"]
        # a curated name that no longer applies says nothing about the model's output
        if unchanged and earlier.get("source") in ("model", "heuristic", None):
            reused = earlier.get("source") == "model" and check_generated_name(
                earlier["name"], description
            )
            if reused:
                result.update(name=reused, source="model")
            yield result
            continue
        yield entry(cve_id, description, title, namer.name([description])[0] or "")


def _build_command(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory() as work_dir:
        print("[+] Downloading name sources", file=sys.stderr)
        nuclei = parse_nuclei(_http_get(NUCLEI_CVES_URL).decode())
        kev = parse_kev(_http_get(KEV_URL).decode())
        ghsa = dict(iter_ghsa_summaries(_download(GHSA_TARBALL_URL, work_dir)))
        references = list(iter_poc_references(_download(POC_TARBALL_URL, work_dir)))

        release = json.loads(_http_get(CVELIST_RELEASE_API))
        assets = [asset["browser_download_url"] for asset in release["assets"]]
        bulk = next(url for url in assets if "all_CVEs_at_midnight" in url)
        cvelist = _download(bulk, work_dir)

        print("[+] Mining community names", file=sys.stderr)
        descriptions = {cve_id: text for cve_id, text, _ in iter_cvelist(cvelist)}
        public_names = mine_public_names(references, descriptions)
        del descriptions

        namer = ModelNamer(args.model, args.threads) if args.model else None
        previous = read_dataset(args.previous) if args.previous else None
        counts: Counter = Counter()
        names = gzip.open(args.names, "wt", encoding="utf-8") if args.names else None
        with gzip.open(args.output, "wt", encoding="utf-8") as output:
            for result in build_dataset(
                iter_cvelist(cvelist), nuclei, kev, ghsa, public_names, namer, previous
            ):
                output.write(json.dumps(result, ensure_ascii=False) + "\n")
                reduced = names_entry(result)
                if names and reduced:
                    names.write(json.dumps(reduced, ensure_ascii=False) + "\n")
                counts[result["source"]] += 1
                done = sum(counts.values())
                if done % 20000 == 0:
                    print(f"[+] {done} records: {dict(counts)}", file=sys.stderr, flush=True)
        if names:
            names.close()
        print(f"[+] Wrote {sum(counts.values())} names: {dict(counts)}", file=sys.stderr)
    return 0


def _name_command(args: argparse.Namespace) -> int:
    namer = ModelNamer(args.model, args.threads) if args.model else None
    resolved = resolve_name(args.description, args.cve or "", namer=namer)
    print(json.dumps(resolved.__dict__, ensure_ascii=False))
    return 0


def _download_model_command(args: argparse.Namespace) -> int:
    print(download_model(args.directory))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    name = commands.add_parser("name", help="name a single vulnerability")
    name.add_argument("description")
    name.add_argument("--cve", help="CVE ID, used to look up its community name")
    name.add_argument("--model", help="directory of the ONNX model")
    name.add_argument("--threads", type=int)
    name.set_defaults(run=_name_command)

    build = commands.add_parser("build", help="build the names dataset from public sources")
    build.add_argument("output", help="output file (.jsonl.gz)")
    build.add_argument("--model", help="directory of the ONNX model")
    build.add_argument("--previous", help="earlier dataset, to reuse model output")
    build.add_argument("--names", help="also write a smaller, names-only file (.jsonl.gz)")
    build.add_argument("--threads", type=int)
    build.set_defaults(run=_build_command)

    model = commands.add_parser("download-model", help="download the published model")
    model.add_argument("directory", nargs="?", help="default: the user cache")
    model.set_defaults(run=_download_model_command)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
