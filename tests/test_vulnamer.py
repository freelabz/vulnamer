import gzip
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vulnamer as V  # noqa: E402

LOG4J_DESC = "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP."


class FakeNamer:
    """Stands in for the ONNX model and records what it was asked to name."""

    def __init__(self, output="Apache Log4j2 - Code Execution"):
        self.output, self.calls = output, []

    def name(self, descriptions):
        self.calls.extend(descriptions)
        return [self.output for _ in descriptions]

    def generate(self, descriptions):
        return self.name(descriptions)


class TestNormalize(unittest.TestCase):
    def test_strips_cve_ids_and_trailing_vulnerability(self):
        self.assertEqual(
            V.normalize_name("Acme Router (CVE-2024-1234) Remote Code Execution Vulnerability"),
            "Acme Router Remote Code Execution",
        )

    def test_rewrites_pipe_and_drops_cwe_suffix(self):
        self.assertEqual(
            V.normalize_name("Lightroom Classic | Path Traversal (CWE-22)"),
            "Lightroom Classic - Path Traversal",
        )

    def test_shortens_long_titles_at_a_clause_boundary(self):
        long_title = "CloudTAK: Authenticated full-read SSRF in routes — " + "x" * 90
        shortened = V.normalize_name(long_title)
        self.assertLessEqual(len(shortened), V.MAX_NAME_LENGTH)
        self.assertTrue(shortened.endswith("routes"))

    def test_strip_versions(self):
        self.assertEqual(
            V.strip_versions("Grafana <= 6.7.1 - Cross-Site Scripting"),
            "Grafana - Cross-Site Scripting",
        )
        self.assertEqual(
            V.strip_versions("Transmission 4.0.0-4.1.2 - Permissive CORS"),
            "Transmission - Permissive CORS",
        )


class TestShellInjection(unittest.TestCase):
    def test_shell_injection_is_a_command_injection(self):
        self.assertEqual(
            V.heuristic_name("Shell injection in AcmeShop 2.1 allows running commands."),
            "AcmeShop - Command Injection",
        )
        self.assertIsNone(V.heuristic_name("Shell injection on Command Error"))


class TestQualityGate(unittest.TestCase):
    def test_accepts_real_names(self):
        for name in (
            "Grafana - Cross-Site Scripting",
            "Use after free in fluidsynth",
            "n8n: Microsoft SQL Node Prototype Pollution",
            "Suricata detect/datasets: reachable assertion",
            "Pillow: OOB read in TiffDecode.c",
        ):
            self.assertTrue(V.is_good_name(name), name)

    def test_rejects_commit_subjects(self):
        for name in (
            "bpf: Reject load-acquire from pointers requiring fault protection",
            "accel/ivpu: Fix general protection fault in ivpu_bo_list()",
            "Fix memory leak in wbrf_record()",
        ):
            self.assertFalse(V.is_good_name(name), name)

    def test_rejects_names_without_a_product(self):
        self.assertFalse(V.is_good_name("RCE via OOM corruption"))
        self.assertFalse(V.is_good_name("RCE via stale global state"))

    def test_rejects_advisory_and_detection_titles(self):
        self.assertFalse(V.is_good_name("Cisco IOS XR Software Security Hardening Release"))
        self.assertFalse(V.is_good_name("Acme Server Multiple Vulnerabilities"))
        self.assertFalse(V.is_good_name("PHP2Shell - Active Crash Detection"))

    def test_requires_product_in_description_when_given(self):
        self.assertFalse(V.is_good_name("Fabrikam Portal - SQL Injection", "A flaw in Acme."))
        self.assertTrue(
            V.is_good_name("Uptime-Kuma - Improper Access Control", "uptime kuma is a monitor")
        )

    def test_vendor_title_is_extracted(self):
        self.assertEqual(
            V.vendor_name(
                "A flaw exists, aka 'Internet Explorer Memory Corruption Vulnerability'."
            ),
            "Internet Explorer Memory Corruption",
        )
        self.assertIsNone(V.vendor_name("No such title here."))


class TestHeuristic(unittest.TestCase):
    def test_older_description_styles(self):
        cases = {
            "SQL injection vulnerability in index.php in FooBar CMS 1.0 allows remote attackers.": "FooBar CMS - SQL Injection",
            "Cross-site scripting (XSS) vulnerability in PunBB before 1.2.5 allows remote attackers.": "PunBB - Cross-Site Scripting",
            "Stack-based buffer overflow in Orbital Viewer 1.04 allows user-assisted attackers.": "Orbital Viewer - Stack Buffer Overflow",
            "Apache Tomcat before 9.0.1 allows remote attackers to read arbitrary files.": "Apache Tomcat - Arbitrary File Read",
        }
        for description, expected in cases.items():
            self.assertEqual(V.heuristic_name(description), expected)

    def test_linux_kernel_commit_style(self):
        prefix = "In the Linux kernel, the following vulnerability has been resolved: "
        self.assertEqual(
            V.linux_kernel_name(
                prefix + "ovl: fix UAF in ovl_do_mkdir. The commit removed a check."
            ),
            "Linux Kernel ovl - Use-After-Free",
        )
        self.assertEqual(
            V.linux_kernel_name(prefix + "platform/x86/amd: Fix memory leak in wbrf_record()"),
            "Linux Kernel platform/x86/amd - Memory Leak",
        )
        self.assertEqual(
            V.linux_kernel_name(prefix + "bpf: Reject load-acquire from pointers"),
            "Linux Kernel bpf: Reject load-acquire from pointers",
        )
        resolved = V.resolve_name(prefix + "ovl: fix UAF in ovl_do_mkdir", namer=FakeNamer())
        self.assertEqual(resolved.source, "kernel")

    def test_no_guess_without_a_known_flaw(self):
        self.assertIsNone(V.heuristic_name("Something odd happens sometimes."))


class TestGeneratedCheck(unittest.TestCase):
    def test_accepts_supported_output(self):
        self.assertEqual(
            V.check_generated_name("Apache Log4j2 2.15.0 - Code Execution", LOG4J_DESC),
            "Apache Log4j2 - Code Execution",
        )

    def test_rejects_invented_product(self):
        self.assertIsNone(V.check_generated_name("Apache Struts - Code Execution", LOG4J_DESC))

    def test_rejects_misspelled_product(self):
        description = "A flaw in openstack-cinder allows denial of service."
        self.assertIsNone(
            V.check_generated_name("opentack-cinder - Denial of Service", description)
        )

    def test_allows_flaw_wording_absent_from_the_description(self):
        description = "Windows Management Services allows a local user to gain privileges."
        self.assertEqual(
            V.check_generated_name(
                "Windows Management Services Elevation of Privilege", description
            ),
            "Windows Management Services Elevation of Privilege",
        )
        self.assertEqual(
            V.check_generated_name("Radiant CMS Cross-site Scripting", "XSS in Radiant CMS."),
            "Radiant CMS Cross-site Scripting",
        )

    def test_rejects_contradicting_flaw(self):
        description = "Langflow allows unauthenticated attackers to execute arbitrary code."
        self.assertIsNone(
            V.check_generated_name("Langflow - Cross-Site Scripting", description)
        )
        csrf = "Grav CMS is vulnerable to cross-site request forgery."
        self.assertIsNone(V.check_generated_name("Grav CMS Remote Code Execution", csrf))

    def test_allows_related_flaw(self):
        traversal = "A path traversal in Ulterius lets attackers read files."
        self.assertEqual(
            V.check_generated_name("Ulterius - Local File Inclusion", traversal),
            "Ulterius - Local File Inclusion",
        )


class TestResolve(unittest.TestCase):
    def test_precedence_prefers_nuclei(self):
        resolved = V.resolve_name(
            LOG4J_DESC,
            nuclei_name="Apache Log4j2 Remote Code Injection",
            kev_name="Apache Log4j2 Remote Code Execution Vulnerability",
            ghsa_summary="Remote code injection in Log4j",
            cna_title="Apache Log4j2 JNDI features",
        )
        self.assertEqual(resolved.name, "Apache Log4j2 Remote Code Injection")
        self.assertEqual(resolved.source, "nuclei")

    def test_nuclei_product_need_not_appear_in_description(self):
        resolved = V.resolve_name(
            "Mobile Security Framework has a flaw.", nuclei_name="MobSF - Path Traversal"
        )
        self.assertEqual((resolved.name, resolved.source), ("MobSF - Path Traversal", "nuclei"))

    def test_poor_tier_falls_through(self):
        resolved = V.resolve_name(
            "PHP has a flaw.",
            nuclei_name="PHP2Shell (CVE-2026-109618/CVE-2026-109619) - Active Crash Detection",
            kev_name="PHP Remote Code Execution Vulnerability",
        )
        self.assertEqual((resolved.name, resolved.source), ("PHP Remote Code Execution", "kev"))

    def test_model_runs_only_without_a_curated_name(self):
        namer = FakeNamer()
        resolved = V.resolve_name(LOG4J_DESC, namer=namer)
        self.assertEqual(resolved.source, "model")
        self.assertEqual(len(namer.calls), 1)

        namer = FakeNamer()
        resolved = V.resolve_name(
            LOG4J_DESC, kev_name="Apache Log4j2 Code Execution", namer=namer
        )
        self.assertEqual(resolved.source, "kev")
        self.assertEqual(namer.calls, [])

    def test_heuristic_when_model_is_absent(self):
        resolved = V.resolve_name(
            "SQL injection vulnerability in Foo CMS 1.0 allows attackers."
        )
        self.assertEqual(
            (resolved.name, resolved.source), ("Foo CMS - SQL Injection", "heuristic")
        )

    def test_public_name_is_independent_of_the_name(self):
        resolved = V.resolve_name(
            LOG4J_DESC, "CVE-2021-44228", nuclei_name="Apache Log4j2 RCE Flaw"
        )
        self.assertEqual(resolved.public_name, "Log4Shell")
        self.assertEqual(resolved.source, "nuclei")

    def test_curated_public_name_beats_mined_spelling(self):
        resolved = V.resolve_name("x", "CVE-2022-0847", public_name="DirtyPipe")
        self.assertEqual(resolved.public_name, "Dirty Pipe")

    def test_nothing_known(self):
        self.assertEqual(V.resolve_name(), V.VulnName(None, None, None))


def repos(cve_id, repository, count, prefix="user"):
    return [(cve_id, f"https://github.com/{prefix}{i}/{repository}") for i in range(count)]


class TestPublicNames(unittest.TestCase):
    def test_finds_coined_name(self):
        references = repos("CVE-2026-1", "PHP2Shell-CVE-2026-1-poc", 8)
        names = V.mine_public_names(references, {"CVE-2026-1": "PHP runtime flaw"})
        self.assertEqual(names, {"CVE-2026-1": "PHP2Shell"})

    def test_requires_independent_owners(self):
        references = [
            ("CVE-2026-1", f"https://github.com/same/PHP2Shell-{i}") for i in range(9)
        ]
        self.assertEqual(V.mine_public_names(references, {}), {})

    def test_rejects_product_names_from_the_description(self):
        references = repos("CVE-2026-1", "GrafanaLabs-poc", 8)
        names = V.mine_public_names(references, {"CVE-2026-1": "GrafanaLabs dashboards flaw"})
        self.assertEqual(names, {})

    def test_rejects_plain_words_and_product_flaw_compounds(self):
        for repository in ("Bomb", "Cheese", "ActiveMQRCE", "LangflowRCE", "AndroidADBD"):
            references = repos("CVE-2026-1", repository, 8)
            self.assertEqual(V.mine_public_names(references, {}), {}, repository)

    def test_rejects_words_shared_by_many_cves(self):
        references = []
        for number in range(V.MAX_NICKNAME_CVES + 1):
            references += repos(f"CVE-2026-{number}", "ExploitKit", 8)
        self.assertEqual(V.mine_public_names(references, {}), {})


class TestParsers(unittest.TestCase):
    def test_nuclei_and_kev(self):
        line = json.dumps({"ID": "CVE-1", "Info": {"Name": "Foo - XSS"}, "file_path": "x"})
        self.assertEqual(V.parse_nuclei(line + "\n"), {"CVE-1": "Foo - XSS"})
        catalog = {"vulnerabilities": [{"cveID": "CVE-1", "vulnerabilityName": "Foo RCE"}]}
        self.assertEqual(V.parse_kev(json.dumps(catalog)), {"CVE-1": "Foo RCE"})

    def test_cve_record(self):
        record = {
            "cveMetadata": {"state": "PUBLISHED", "cveId": "CVE-1"},
            "containers": {
                "cna": {
                    "title": "Foo  XSS",
                    "descriptions": [
                        {"lang": "fr", "value": "ignorer"},
                        {"lang": "en-US", "value": "Foo has\nXSS."},
                    ],
                }
            },
        }
        self.assertEqual(V.parse_cve_record(record), ("CVE-1", "Foo has\nXSS.", "Foo XSS"))
        record["cveMetadata"]["state"] = "REJECTED"
        self.assertIsNone(V.parse_cve_record(record))

    def test_nested_bulk_archive(self):
        record = {
            "cveMetadata": {"state": "PUBLISHED", "cveId": "CVE-1"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Foo"}]}},
        }
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("cves/2026/1xxx/CVE-1.json", json.dumps(record))
            archive.writestr("cves/2026/1xxx/CVE-2.json", "{broken")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bulk.zip")
            with zipfile.ZipFile(path, "w") as outer:
                outer.writestr("cves.zip", inner.getvalue())
            self.assertEqual(list(V.iter_cvelist(path)), [("CVE-1", "Foo", "")])

    def _cve(self, cve_id, description, state="PUBLISHED", published="2026-11-24T10:00:00.000Z"):
        return {
            "cveMetadata": {"state": state, "cveId": cve_id, "datePublished": published},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": description}]}},
        }

    def _zip(self, directory, name, records, nested=False):
        path = os.path.join(directory, name)
        content = io.BytesIO() if nested else path
        with zipfile.ZipFile(content, "w") as archive:
            for record in records:
                archive.writestr(f"deltaCves/{record['cveMetadata']['cveId']}.json", json.dumps(record))
        if nested:
            with zipfile.ZipFile(path, "w") as outer:
                outer.writestr("cves.zip", content.getvalue())
        return path

    def test_delta_overrides_bulk(self):
        with tempfile.TemporaryDirectory() as directory:
            bulk = self._zip(
                directory,
                "bulk.zip",
                [self._cve("CVE-1", "Old"), self._cve("CVE-2", "Kept"), self._cve("CVE-3", "Withdrawn")],
            )
            delta = self._zip(
                directory,
                "delta.zip",
                [self._cve("CVE-1", "New"), self._cve("CVE-4", "Today"), self._cve("CVE-3", "", "REJECTED")],
            )
            self.assertEqual(
                sorted(V.iter_cvelist(bulk, delta)),
                [("CVE-1", "New", ""), ("CVE-2", "Kept", ""), ("CVE-4", "Today", "")],
            )
            # without a delta the bulk archive is read as is
            self.assertEqual([cve[0] for cve in V.iter_cvelist(bulk)], ["CVE-1", "CVE-2", "CVE-3"])

    def test_delta_rejected_cve_not_in_bulk(self):
        with tempfile.TemporaryDirectory() as directory:
            bulk = self._zip(directory, "bulk.zip", [self._cve("CVE-1", "Foo")])
            delta = self._zip(directory, "delta.zip", [self._cve("CVE-2", "", "REJECTED")])
            self.assertEqual(list(V.iter_cvelist(bulk, delta)), [("CVE-1", "Foo", "")])

    def _build(self, directory, published, delta_day="2026-11-25"):
        bulk = self._zip(directory, "bulk.zip", [self._cve("CVE-1", "Foo", published="2026-11-23T10:00:00Z")], nested=True)
        delta = self._zip(directory, "delta.zip", [self._cve("CVE-2", "Bar", published=published)])
        release = {
            "assets": [
                {"browser_download_url": f"https://x/{delta_day}_delta_CVEs_at_1200Z.zip"},
                {"browser_download_url": "https://x/2026-11-25_all_CVEs_at_midnight.zip.zip"},
            ]
        }
        responses = {V.NUCLEI_CVES_URL: b"", V.KEV_URL: b"{}", V.CVELIST_RELEASE_API: json.dumps(release).encode()}
        downloads = {release["assets"][1]["browser_download_url"]: bulk, release["assets"][0]["browser_download_url"]: delta}
        output = os.path.join(directory, "out.jsonl.gz")
        args = mock.Mock(output=output, names=None, model=None, previous=None, threads=None)
        stderr = io.StringIO()
        with (
            mock.patch.object(V, "_http_get", side_effect=responses.__getitem__),
            mock.patch.object(V, "_download", side_effect=lambda url, _: downloads.get(url, "")),
            mock.patch.object(V, "iter_ghsa_summaries", return_value=[]),
            mock.patch.object(V, "iter_poc_references", return_value=[]),
            mock.patch.object(V.time, "time", return_value=1795608000),  # 2026-11-25T12:00:00Z
            redirect_stderr(stderr),
        ):
            code = V._build_command(args)
        return code, output, stderr.getvalue()

    def test_build_reads_the_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            code, output, _ = self._build(directory, "2026-11-25T01:00:00.000Z")
            self.assertEqual(code, 0)
            self.assertEqual(sorted(row["id"] for row in V.read_dataset(output).values()), ["CVE-1", "CVE-2"])

    def test_build_fails_on_a_stale_cve_list(self):
        with tempfile.TemporaryDirectory() as directory:
            code, output, stderr = self._build(directory, "2026-11-23T23:00:00.000Z")
            self.assertEqual(code, 1)
            self.assertIn("stale", stderr)
            self.assertFalse(os.path.exists(output))

    def test_build_ignores_a_delta_of_another_day(self):
        with tempfile.TemporaryDirectory() as directory:
            # the bulk archive alone is 50 h old: the delta of the day before must not be read
            code, _, stderr = self._build(directory, "2026-11-25T01:00:00.000Z", delta_day="2026-11-24")
            self.assertEqual(code, 1)
            self.assertIn("2026-11-23T10:00:00Z", stderr)

    def _tarball(self, directory, files):
        path = os.path.join(directory, "data.tar.gz")
        with tarfile.open(path, "w:gz") as archive:
            for name, content in files.items():
                data = json.dumps(content).encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def test_ghsa_only_reads_reviewed_advisories(self):
        reviewed = {"summary": "Foo XSS", "aliases": ["CVE-1", "OTHER-1"]}
        with tempfile.TemporaryDirectory() as directory:
            path = self._tarball(
                directory,
                {
                    "db/advisories/github-reviewed/2026/a/a.json": reviewed,
                    "db/advisories/unreviewed/2026/b/b.json": {
                        "summary": "x",
                        "aliases": ["CVE-2"],
                    },
                },
            )
            self.assertEqual(list(V.iter_ghsa_summaries(path)), [("CVE-1", "Foo XSS")])

    def test_poc_references(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._tarball(
                directory,
                {"repo/2026/CVE-2026-1.json": [{"html_url": "https://github.com/a/b"}]},
            )
            self.assertEqual(
                list(V.iter_poc_references(path)), [("CVE-2026-1", "https://github.com/a/b")]
            )


class TestBuildDataset(unittest.TestCase):
    RECORDS = [
        ("CVE-1", "Foo has an odd flaw.", ""),
        ("CVE-2", "Bar has an odd flaw.", "Bar Portal - Stored XSS"),
    ]

    def test_model_only_sees_uncovered_records(self):
        namer = FakeNamer("Foo - Odd Flaw")
        rows = {r["id"]: r for r in V.build_dataset(self.RECORDS, {}, {}, {}, {}, namer)}
        self.assertEqual(namer.calls, ["Foo has an odd flaw."])
        self.assertEqual(rows["CVE-1"]["source"], "model")
        self.assertEqual(rows["CVE-2"]["source"], "cna")

    def test_published_curated_name_survives_a_changed_source_title(self):
        description = "Foo has an odd flaw."
        previous = {
            "CVE-1": {
                "id": "CVE-1",
                "name": "Foo Portal - Stored XSS",
                "source": "ghsa",
                "description_hash": V.description_hash(description),
            }
        }
        namer = FakeNamer("Foo - Odd Flaw")
        ghsa = {"CVE-1": "Foo Portal - Reflected Cross-Site Scripting In Search"}
        rows = list(
            V.build_dataset([("CVE-1", description, "")], {}, {}, ghsa, {}, namer, previous)
        )
        self.assertEqual((rows[0]["name"], rows[0]["source"]), ("Foo Portal - Stored XSS", "ghsa"))
        self.assertEqual(namer.calls, [])

    def test_published_curated_name_survives_its_source_disappearing(self):
        previous = {"CVE-2": {"id": "CVE-2", "name": "Bar Portal - Stored XSS", "source": "cna"}}
        rows = list(
            V.build_dataset([("CVE-2", "Bar has an odd flaw.", "")], {}, {}, {}, {}, None, previous)
        )
        self.assertEqual((rows[0]["name"], rows[0]["source"]), ("Bar Portal - Stored XSS", "cna"))
        self.assertEqual(rows[0]["description_hash"], V.description_hash("Bar has an odd flaw."))

    def test_model_names_one_description_at_a_time(self):
        class OneAtATime(FakeNamer):
            def name(self, descriptions):
                assert len(descriptions) == 1
                return super().name(descriptions)

        records = [(f"CVE-{n}", f"Foo{n} has an odd flaw.", "") for n in range(3)]
        rows = list(V.build_dataset(records, {}, {}, {}, {}, OneAtATime("Foo - Odd Flaw")))
        self.assertEqual([row["id"] for row in rows], ["CVE-0", "CVE-1", "CVE-2"])

    def test_names_file_keeps_only_what_a_lookup_needs(self):
        full = {
            "id": "CVE-1",
            "name": "Foo - Odd Flaw",
            "source": "model",
            "public_name": "FooShell",
            "description_hash": "abc",
        }
        self.assertEqual(
            V.names_entry(full),
            {"id": "CVE-1", "name": "Foo - Odd Flaw", "public_name": "FooShell"},
        )
        self.assertEqual(
            V.names_entry({"id": "CVE-2", "name": "Foo - Odd Flaw", "source": "cna"}),
            {"id": "CVE-2", "name": "Foo - Odd Flaw"},
        )
        self.assertEqual(
            V.names_entry({"id": "CVE-3", "name": None, "public_name": "FooShell"}),
            {"id": "CVE-3", "public_name": "FooShell"},
        )
        self.assertIsNone(V.names_entry({"id": "CVE-4", "name": None, "source": None}))

    def test_unchanged_description_reuses_earlier_output(self):
        namer = FakeNamer("New output")
        previous = {
            "CVE-1": {
                "id": "CVE-1",
                "name": "Foo - Odd Flaw",
                "source": "model",
                "description_hash": V.description_hash("Foo has an odd flaw."),
            }
        }
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, namer, previous))
        self.assertEqual(rows[0]["name"], "Foo - Odd Flaw")
        self.assertEqual(namer.calls, [])

    def test_published_name_is_kept_even_if_the_guard_now_rejects_it(self):
        previous = {
            "CVE-1": {
                "name": "Invented Product - Odd Flaw",
                "source": "model",
                "description_hash": V.description_hash("Foo has an odd flaw."),
            }
        }
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, FakeNamer(), previous))
        self.assertEqual(rows[0]["name"], "Invented Product - Odd Flaw")

    def test_published_model_name_survives_a_changed_description(self):
        namer = FakeNamer("Foo - Odd Flaw")
        previous = {"CVE-1": {"name": "Old", "source": "model", "description_hash": "0"}}
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, namer, previous))
        self.assertEqual((rows[0]["name"], rows[0]["source"]), ("Old", "model"))
        self.assertEqual(rows[0]["description_hash"], V.description_hash("Foo has an odd flaw."))
        self.assertEqual(namer.calls, [])

    def test_unnamed_cve_with_a_changed_description_runs_the_model_again(self):
        namer = FakeNamer("Foo - Odd Flaw")
        previous = {"CVE-1": {"id": "CVE-1", "name": None, "source": None, "description_hash": "0"}}
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, namer, previous))
        self.assertEqual((rows[0]["name"], rows[0]["source"]), ("Foo - Odd Flaw", "model"))
        self.assertEqual(len(namer.calls), 1)

    def test_unnamed_cve_with_an_unchanged_description_skips_the_model(self):
        namer = FakeNamer("Foo - Odd Flaw")
        previous = {
            "CVE-1": {
                "id": "CVE-1",
                "name": None,
                "source": None,
                "description_hash": V.description_hash("Foo has an odd flaw."),
            }
        }
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, namer, previous))
        self.assertIsNone(rows[0]["name"])
        self.assertEqual(namer.calls, [])

    def test_unnamed_cve_can_get_its_first_name_from_a_new_source(self):
        previous = {"CVE-1": {"id": "CVE-1", "name": None, "source": None}}
        nuclei = {"CVE-1": "Foo Server - Remote Code Execution"}
        rows = list(V.build_dataset(self.RECORDS[:1], nuclei, {}, {}, {}, None, previous))
        self.assertEqual(
            (rows[0]["name"], rows[0]["source"]), ("Foo Server - Remote Code Execution", "nuclei")
        )

    def test_public_name_is_frozen_once_published(self):
        previous = {
            "CVE-1": {"id": "CVE-1", "name": "Foo - Odd Flaw", "source": "model"},
            "CVE-2": {"id": "CVE-2", "name": "Bar Portal - Stored XSS", "source": "cna",
                      "public_name": "BarBleed"},
        }
        mined = {"CVE-1": "FooShell", "CVE-2": "BarShell"}
        rows = {r["id"]: r for r in V.build_dataset(self.RECORDS, {}, {}, {}, mined, None, previous)}
        self.assertNotIn("public_name", rows["CVE-1"])  # adding one would change the display
        self.assertEqual(rows["CVE-2"]["public_name"], "BarBleed")

    def test_public_name_only_entry_is_frozen(self):
        previous = {"CVE-1": {"id": "CVE-1", "name": None, "source": None, "public_name": "FooShell"}}
        nuclei = {"CVE-1": "Foo Server - Remote Code Execution"}
        rows = list(V.build_dataset(self.RECORDS[:1], nuclei, {}, {}, {}, None, previous))
        self.assertEqual((rows[0]["name"], rows[0]["public_name"]), (None, "FooShell"))

    def test_published_cve_missing_from_the_records_is_carried_forward(self):
        previous = {
            "CVE-9": {"id": "CVE-9", "name": "Gone - Odd Flaw", "source": "model",
                      "public_name": "GoneShell", "description_hash": "abc"},
            "CVE-8": {"id": "CVE-8", "name": None, "source": None},
        }
        rows = {r["id"]: r for r in V.build_dataset(self.RECORDS, {}, {}, {}, {}, None, previous)}
        self.assertEqual(rows["CVE-9"], previous["CVE-9"])
        self.assertNotIn("CVE-8", rows)  # nothing was published for it
        self.assertEqual(rows["CVE-2"]["name"], "Bar Portal - Stored XSS")  # new CVEs still named

    def test_rebuild_passes_the_stability_check(self):
        first = {r["id"]: r for r in V.build_dataset(self.RECORDS, {}, {}, {}, {}, FakeNamer("Foo - Odd Flaw"))}
        records = [("CVE-1", "Foo has a different flaw now.", ""), ("CVE-3", "Baz has an odd flaw.", "")]
        second = {
            r["id"]: r
            for r in V.build_dataset(records, {}, {}, {}, {"CVE-1": "FooShell"}, FakeNamer("Baz - Odd Flaw"), first)
        }
        self.assertEqual(V.stability_errors(first, second), [])
        self.assertEqual(second["CVE-3"]["name"], "Baz - Odd Flaw")

    def test_rejected_model_output_falls_back(self):
        record = [("CVE-1", "SQL injection vulnerability in Foo CMS 1.0 allows attackers.", "")]
        rows = list(V.build_dataset(record, {}, {}, {}, {}, FakeNamer(None)))
        self.assertEqual(
            (rows[0]["name"], rows[0]["source"]), ("Foo CMS - SQL Injection", "heuristic")
        )

    def test_no_model_needed(self):
        rows = list(V.build_dataset(self.RECORDS, {}, {}, {}, {"CVE-1": "FooShell"}))
        self.assertEqual(rows[0]["public_name"], "FooShell")
        self.assertIsNone(rows[0]["name"])

    def test_dataset_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "names.jsonl.gz")
            with gzip.open(path, "wt", encoding="utf-8") as output:
                output.write(
                    json.dumps({"id": "CVE-1", "name": "Foo Bär"}, ensure_ascii=False) + "\n"
                )
            self.assertEqual(V.read_dataset(path)["CVE-1"]["name"], "Foo Bär")


def _write_dataset(path, rows):
    with gzip.open(path, "wt", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row) + "\n")


class TestCheckStable(unittest.TestCase):
    PREVIOUS = {
        "CVE-1": {"id": "CVE-1", "name": "Foo - Odd Flaw", "source": "model"},
        "CVE-2": {"id": "CVE-2", "name": None, "source": None, "public_name": "BarShell"},
        "CVE-3": {"id": "CVE-3", "name": None, "source": None},
    }

    def test_identical_data_is_stable(self):
        self.assertEqual(V.stability_errors(self.PREVIOUS, dict(self.PREVIOUS)), [])

    def test_appended_data_is_stable(self):
        new = {
            **self.PREVIOUS,
            "CVE-3": {"id": "CVE-3", "name": "Baz - Odd Flaw", "source": "model"},
            "CVE-4": {"id": "CVE-4", "name": "Qux - Odd Flaw", "source": "model"},
        }
        new["CVE-1"] = {**new["CVE-1"], "description_hash": "x"}
        self.assertEqual(V.stability_errors(self.PREVIOUS, new), [])

    def test_changed_source_fails(self):
        new = {**self.PREVIOUS, "CVE-1": {**self.PREVIOUS["CVE-1"], "source": "kev"}}
        self.assertEqual(V.stability_errors(self.PREVIOUS, new), ["CVE-1: source 'model' -> 'kev'"])

    def test_min_files_without_source_compare(self):
        previous = {"CVE-1": {"id": "CVE-1", "name": "Foo - Odd Flaw"}}
        self.assertEqual(V.stability_errors(previous, dict(previous)), [])

    def test_changed_name_fails(self):
        new = {**self.PREVIOUS, "CVE-1": {"id": "CVE-1", "name": "Foo - Other Flaw", "source": "model"}}
        self.assertEqual(
            V.stability_errors(self.PREVIOUS, new),
            ["CVE-1: name 'Foo - Odd Flaw' -> 'Foo - Other Flaw'"],
        )

    def test_added_or_changed_public_name_fails(self):
        new = {
            **self.PREVIOUS,
            "CVE-1": {**self.PREVIOUS["CVE-1"], "public_name": "FooShell"},
            "CVE-2": {**self.PREVIOUS["CVE-2"], "public_name": "BarBleed"},
        }
        self.assertEqual(len(V.stability_errors(self.PREVIOUS, new)), 2)

    def test_removed_name_fails(self):
        new = {k: v for k, v in self.PREVIOUS.items() if k != "CVE-2"}
        self.assertEqual(V.stability_errors(self.PREVIOUS, new), ["CVE-2: missing (was None)"])
        new = {**self.PREVIOUS, "CVE-1": {"id": "CVE-1", "name": None, "source": "model"}}
        self.assertEqual(len(V.stability_errors(self.PREVIOUS, new)), 1)

    def test_command_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            old, same, changed = (os.path.join(directory, f"{n}.jsonl.gz") for n in "abc")
            _write_dataset(old, self.PREVIOUS.values())
            _write_dataset(same, self.PREVIOUS.values())
            _write_dataset(changed, [{"id": "CVE-1", "name": "Renamed"}])
            with redirect_stderr(io.StringIO()):
                self.assertEqual(V.main(["check-stable", old, same]), 0)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(V.main(["check-stable", old, changed]), 1)
            self.assertIn("CVE-1: name 'Foo - Odd Flaw' -> 'Renamed'", stderr.getvalue())


class TestHttpGet(unittest.TestCase):
    def headers_sent(self, url, env):
        sent = {}

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(request, timeout):
            sent.update({k.lower(): v for k, v in request.header_items()})
            sent["_redirected"] = {k.lower() for k in request.headers}
            return Response(b"{}")

        with mock.patch.object(V.urllib.request, "urlopen", urlopen), mock.patch.dict(
            os.environ, env, clear=True
        ):
            V._http_get(url)
        return sent

    def test_github_api_gets_the_token(self):
        for name in ("GITHUB_TOKEN", "GH_TOKEN"):
            sent = self.headers_sent(V.CVELIST_RELEASE_API, {name: "secret"})
            self.assertEqual(sent["authorization"], "Bearer secret")
            self.assertNotIn("authorization", sent["_redirected"])  # not forwarded on redirect

    def test_token_stays_off_other_hosts_and_is_optional(self):
        self.assertNotIn("authorization", self.headers_sent(V.KEV_URL, {"GITHUB_TOKEN": "secret"}))
        self.assertNotIn("authorization", self.headers_sent(V.CVELIST_RELEASE_API, {}))


class TestRealWorldShapes(unittest.TestCase):
    """Regressions found by reading the first full dataset build."""

    KERNEL = (
        "In the Linux kernel, the following vulnerability has been resolved:\n\n"
        "{}\n\nSyzbot reported a hang issue in migrate_pages_batch() called by mbind().\n"
    )

    def test_kernel_subject_stops_at_end_of_line(self):
        name = V.linux_kernel_name(
            self.KERNEL.format("drop_monitor: fix incorrect initialization order")
        )
        self.assertEqual(name, "Linux Kernel drop_monitor: fix incorrect initialization order")

    def test_kernel_flaw_comes_from_subject_not_body(self):
        name = V.linux_kernel_name(self.KERNEL.format("dlm: fix plock invalid read"))
        self.assertEqual(name, "Linux Kernel dlm: fix plock invalid read")

    def test_kernel_long_subject_is_not_cut_down_to_the_subsystem(self):
        subject = "drm/amd/pm: " + "update the intermediate power state " * 5
        name = V.linux_kernel_name(self.KERNEL.format(subject.strip()))
        self.assertTrue(name.startswith("Linux Kernel drm/amd/pm: update the"), name)
        self.assertLessEqual(len(name), V.MAX_NAME_LENGTH)

    def test_kernel_description_flattened_to_one_line(self):
        flat = V._collapse(self.KERNEL.format("nilfs2: fix hang in lookup")).replace(
            "lookup Syzbot", "lookup. Syzbot"
        )
        self.assertEqual(V.linux_kernel_name(flat), "Linux Kernel nilfs2: fix hang in lookup")

    def test_heuristic_skips_sentence_openers(self):
        self.assertEqual(
            V.heuristic_name(
                "The Ultimate Store Kit plugin is vulnerable to Cross-Site Request Forgery"
            ),
            "Ultimate Store Kit - Cross-Site Request Forgery",
        )
        self.assertEqual(
            V.heuristic_name("In Yubico PIV Tool an attacker can read sensitive information"),
            "Yubico PIV Tool - Information Disclosure",
        )
        self.assertIsNone(
            V.heuristic_name(
                "This vulnerability allows remote attackers to execute arbitrary code"
            )
        )

    def test_heuristic_reads_browser_style_descriptions(self):
        self.assertEqual(
            V.heuristic_name(
                "Use after free in USB in Google Chrome prior to 86.0.4240.99 allowed a remote attacker"
            ),
            "Google Chrome - Use-After-Free",
        )
        self.assertEqual(
            V.heuristic_name(
                "Inappropriate implementation in JavaScript in Google Chrome prior to 76.0 allowed spoofing"
            ),
            "Google Chrome - Inappropriate Implementation",
        )

    def test_heuristic_does_not_take_a_flaw_for_a_product(self):
        self.assertIsNone(V.heuristic_name("Out-of-bounds read could cause a crash"))
        self.assertIsNone(
            V.heuristic_name("Unauthenticated Cross Site Scripting in the search box")
        )

    def test_heuristic_keeps_products_made_of_flaw_words(self):
        self.assertEqual(
            V.heuristic_name("SQL Server allows remote attackers to cause a denial of service"),
            "SQL Server - Denial of Service",
        )

    def test_heuristic_reads_apple_style_descriptions(self):
        self.assertEqual(
            V.heuristic_name(
                "A use after free issue was addressed with improved memory management. "
                "This issue is fixed in watchOS 7.0, iOS 14.0 and iPadOS 14.0."
            ),
            "Apple watchOS - Use-After-Free",
        )

    def test_generated_name_drops_oracle_boilerplate(self):
        description = "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server). Easily exploitable."
        self.assertEqual(
            V.check_generated_name(
                "MySQL Server product of Oracle MySQL - Denial of Service", description
            ),
            "MySQL Server - Denial of Service",
        )

    def test_generated_vendor_implied_by_product(self):
        self.assertEqual(
            V.check_generated_name(
                "Apple Multiple Products Use-After-Free",
                "A use after free issue was addressed. This issue is fixed in iOS 14.0.",
            ),
            "Apple Multiple Products Use-After-Free",
        )
        self.assertEqual(
            V.check_generated_name(
                "Google Chromium Blink Use-After-Free",
                "Use after free in Blink in Google Chrome prior to 89.0 allowed a remote attacker",
            ),
            "Google Chromium Blink Use-After-Free",
        )

    def test_generated_name_drops_component_boilerplate(self):
        description = "Vulnerability in the Oracle Agile PLM component of Oracle Supply Chain Products Suite."
        self.assertEqual(
            V.check_generated_name(
                "Oracle Agile PLM component of Oracle Supply Chain Products Suite - Denial of Service",
                description,
            ),
            "Oracle Agile PLM - Denial of Service",
        )

    def test_rejects_generation_loops(self):
        self.assertIsNone(
            V.check_generated_name(
                "Open edX Platform: Authenticated Authenticated Authenticated Username",
                "Open edX Platform lets an Authenticated user change a Username.",
            )
        )
        self.assertIsNone(
            V.check_generated_name(
                "RuoYi-Vue: yangzongzhuan RuoYi-Vue: getMen",
                "A flaw in yangzongzhuan RuoYi-Vue affects the function getMen.",
            )
        )

    def test_repairs_a_doubled_word(self):
        self.assertEqual(
            V.check_generated_name(
                "Magento Time-of-check Time-of-check Time-of-use Race Condition",
                "A Time-of-check Time-of-use race condition in Magento.",
            ),
            "Magento Time-of-check Time-of-use Race Condition",
        )

    def test_flaw_words_may_recur_in_chained_flaws(self):
        self.assertEqual(
            V.check_generated_name(
                "AuthorSure - Cross-Site Request Forgery to Stored Cross-Site Scripting",
                "The AuthorSure plugin has a cross-site request forgery leading to stored cross-site scripting.",
            ),
            "AuthorSure - Cross-Site Request Forgery to Stored Cross-Site Scripting",
        )

    def test_rejects_cut_off_output(self):
        self.assertIsNone(
            V.check_generated_name(
                "IBM Db2 Genius Hub is affected by multiple",
                "IBM Db2 Genius Hub is affected by multiple vulnerabilities in libraries.",
            )
        )

    def test_vulnerability_words_may_repeat(self):
        self.assertEqual(
            V.check_generated_name(
                "ArubaOS Remote Access Point - Remote Code Execution",
                "ArubaOS Remote Access Point allows remote code execution.",
            ),
            "ArubaOS Remote Access Point - Remote Code Execution",
        )

    def test_long_title_is_not_left_hanging_on_a_verb(self):
        title = (
            "nvm use --save and nvm install --save write through a symlinked .nvmrc " + "x" * 60
        )
        self.assertNotEqual(
            V.shorten_name(title), "nvm use --save and nvm install --save write"
        )

    def test_implied_vendor_needs_its_evidence(self):
        self.assertIsNone(
            V.check_generated_name("Apple Foo - Use-After-Free", "Use after free in libfoo.")
        )

    def test_reused_model_name_goes_through_the_guard_again(self):
        description = (
            "Vulnerability in the MySQL Server product of Oracle MySQL. Easily exploitable."
        )
        previous = {
            "CVE-1": {
                "name": "MySQL Server product of Oracle MySQL - Denial of Service",
                "source": "model",
                "description_hash": V.description_hash(description),
            }
        }
        namer = FakeNamer()
        rows = list(
            V.build_dataset([("CVE-1", description, "")], {}, {}, {}, {}, namer, previous)
        )
        # published names are append-only, so the guard does not rewrite them
        self.assertEqual(rows[0]["name"], previous["CVE-1"]["name"])
        self.assertEqual(namer.calls, [])
        # but a name produced for the first time does go through it
        self.assertEqual(
            V.check_generated_name(previous["CVE-1"]["name"], description),
            "MySQL Server - Denial of Service",
        )


class TestKernelThroughThePipeline(unittest.TestCase):
    def test_commit_subject_survives_parsing(self):
        text = (
            "In the Linux kernel, the following vulnerability has been resolved:\n\n"
            "drop_monitor: fix incorrect initialization order\n\n"
            "Syzkaller reports the following bug:\n\nBUG: spinlock bad magic\n"
        )
        record = {
            "cveMetadata": {"state": "PUBLISHED", "cveId": "CVE-1"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": text}]}},
        }
        rows = list(V.build_dataset([V.parse_cve_record(record)], {}, {}, {}, {}))
        self.assertEqual(rows[0]["source"], "kernel")
        self.assertEqual(
            rows[0]["name"], "Linux Kernel drop_monitor: fix incorrect initialization order"
        )

    def test_hash_ignores_whitespace(self):
        self.assertEqual(V.description_hash("a\n\nb "), V.description_hash("a b"))


class TestVendorNames(unittest.TestCase):
    def test_keeps_vendor_titles(self):
        for title in (
            "Windows Kernel Information Disclosure",
            "cloneNode Remote Code Execution",
            "iSNS Server Memory Corruption",
        ):
            description = f"A flaw in Windows and iSNS, aka '{title}'."
            self.assertEqual(V.vendor_name(description), title)

    def test_rejects_phrases_that_are_not_titles(self):
        for phrase in (
            "the second issue",
            "unsigned long long[18]",
            "Keyboard Layout",
            "registered user privilege escalation",
        ):
            self.assertIsNone(V.vendor_name(f"A flaw in Keyboard handling, aka '{phrase}'."))

    def test_rejected_phrase_falls_through_to_the_model(self):
        description = "Foo Server has a buffer overflow, aka 'the second issue'."
        result = V.resolve_name(description, namer=FakeNamer("Foo Server - Buffer Overflow"))
        self.assertEqual(result.source, "model")


DATASET_ROWS = [
    {"id": "CVE-2026-109618", "name": "PHP Memory Corruption", "source": "kev", "public_name": "PHP2Shell"},
    {"id": "CVE-2026-1000", "name": "Foo - Odd Flaw", "source": "model"},
    {"id": "CVE-2026-10000", "name": None, "source": None, "public_name": "FooShell"},
]


class DatasetCache(unittest.TestCase):
    """Points the cache at a temporary directory and serves a small dataset."""

    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": work.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.source = os.path.join(work.name, "published.jsonl.gz")
        with gzip.open(self.source, "wt", encoding="utf-8") as output:
            for row in DATASET_ROWS:
                output.write(json.dumps(row) + "\n")
        self.downloads = 0
        self.fail_download = False
        patcher = mock.patch.object(V, "_download", self.fake_download)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_download(self, url, directory):
        self.assertEqual(url, V.DATASET_URL)
        self.downloads += 1
        if self.fail_download:
            raise OSError("network is unreachable")
        path = os.path.join(directory, "download")
        shutil.copyfile(self.source, path)
        return path

    def age_cache(self, seconds):
        path = os.path.join(V.cache_dir(), "vuln_names.jsonl.gz")
        old = os.path.getmtime(path) - seconds
        os.utime(path, (old, old))


class TestLookup(DatasetCache):
    def test_downloads_once_then_reads_the_cache(self):
        found = V.lookup_name("CVE-2026-109618")
        self.assertEqual(found, V.VulnName("PHP Memory Corruption", "kev", "PHP2Shell"))
        self.assertEqual(V.lookup_name("cve-2026-1000").source, "model")
        self.assertEqual(self.downloads, 1)

    def test_unlisted_cve(self):
        self.assertIsNone(V.lookup_name("CVE-2099-0001"))

    def test_id_prefix_does_not_match_a_longer_id(self):
        self.assertEqual(V.lookup_name("CVE-2026-1000").name, "Foo - Odd Flaw")
        self.assertEqual(V.lookup_name("CVE-2026-10000").public_name, "FooShell")

    def test_stale_cache_is_refreshed(self):
        V.lookup_name("CVE-2026-1000")
        self.age_cache(V.DATASET_MAX_AGE + 60)
        V.lookup_name("CVE-2026-1000")
        self.assertEqual(self.downloads, 2)

    def test_failed_refresh_keeps_the_stale_copy(self):
        V.lookup_name("CVE-2026-1000")
        self.age_cache(V.DATASET_MAX_AGE + 60)
        self.fail_download = True
        with self.assertLogs("vulnamer", "WARNING"):
            self.assertEqual(V.lookup_name("CVE-2026-1000").name, "Foo - Odd Flaw")

    def test_failed_first_download_raises(self):
        self.fail_download = True
        with self.assertRaises(OSError):
            V.lookup_name("CVE-2026-1000")

    def test_offline_uses_a_stale_copy_without_downloading(self):
        V.lookup_name("CVE-2026-1000")
        self.age_cache(V.DATASET_MAX_AGE * 30)
        self.assertEqual(V.lookup_name("CVE-2026-1000", offline=True).name, "Foo - Odd Flaw")
        self.assertEqual(self.downloads, 1)

    def test_offline_without_a_copy_raises(self):
        with self.assertRaises(FileNotFoundError):
            V.lookup_name("CVE-2026-1000", offline=True)
        self.assertEqual(self.downloads, 0)


class TestNameCommand(DatasetCache):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = V.main(["name", *argv])
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_looks_up_a_cve(self):
        code, result, err = self.run_cli("CVE-2026-109618")
        self.assertEqual(code, 0)
        self.assertEqual(
            result, {"name": "PHP Memory Corruption", "source": "kev", "public_name": "PHP2Shell"}
        )
        self.assertEqual(err, "")

    def test_dataset_name_wins_over_the_description(self):
        _, result, _ = self.run_cli("CVE-2026-1000", "-d", "SQL injection in AcmeShop 2.1 login.")
        self.assertEqual(result["source"], "model")
        self.assertEqual(result["name"], "Foo - Odd Flaw")

    def test_unlisted_cve_names_the_description(self):
        _, result, _ = self.run_cli("CVE-2099-0001", "-d", "SQL injection in AcmeShop 2.1 login.")
        self.assertEqual(result["source"], "heuristic")

    def test_unnamed_listed_cve_keeps_its_public_name(self):
        _, result, _ = self.run_cli("CVE-2026-10000", "-d", "SQL injection in AcmeShop 2.1 login.")
        self.assertEqual(result["source"], "heuristic")
        _, result, _ = self.run_cli("CVE-2026-10000")
        self.assertEqual(result, {"name": None, "source": None, "public_name": "FooShell"})

    def test_description_alone(self):
        _, result, _ = self.run_cli("--description", "SQL injection in AcmeShop 2.1 login.")
        self.assertEqual(result["source"], "heuristic")
        self.assertEqual(self.downloads, 0)

    def test_offline_without_a_dataset_falls_back_to_the_description(self):
        _, result, err = self.run_cli(
            "CVE-2026-1000", "--offline", "-v", "-d", "SQL injection in AcmeShop 2.1 login."
        )
        self.assertEqual(result["source"], "heuristic")
        self.assertIn("unavailable", err)

    def test_verbose_shows_each_step_on_stderr(self):
        _, _, err = self.run_cli("CVE-2099-0001", "-v", "-d", "SQL injection in AcmeShop 2.1 login.")
        for step in ("dataset: downloading", "is not listed", "nuclei, kev, ghsa, cna: no titles", "heuristic: accepted"):
            self.assertIn(step, err)
        self.assertTrue(all(line.startswith("[vulnamer] ") for line in err.splitlines()))
        self.assertNotIn("nuclei: nothing given", err)
        self.assertEqual(V.log.handlers, [])

    def test_no_hint_when_a_name_is_found(self):
        _, result, err = self.run_cli("-d", "Shell injection in AcmeShop 2.1.")
        self.assertEqual(result["name"], "AcmeShop - Command Injection")
        self.assertEqual(err, "")

    def test_hint_for_free_text_without_the_model(self):
        with mock.patch.object(V, "_model_installed", return_value=False):
            _, result, err = self.run_cli("-d", "Shell injection on Command Error")
        self.assertIsNone(result["name"])
        self.assertIn("vulnamer: no name found.", err)
        self.assertIn("Pass a CVE ID to use the nightly dataset.", err)
        self.assertIn('Install "vulnamer[model]" and add --model', err)
        with mock.patch.object(V, "_model_installed", return_value=True):
            _, _, err = self.run_cli("-d", "Shell injection on Command Error")
        self.assertIn("Add --model to run the model", err)
        self.assertNotIn("Install", err)

    def test_hint_when_the_model_could_not_name_it(self):
        fake = FakeNamer("Command Error in Command Error")
        with mock.patch.object(V, "ModelNamer", lambda *args: fake):
            _, result, err = self.run_cli("-d", "Shell injection on Command Error", "--model", "dir")
        self.assertEqual(fake.calls, ["Shell injection on Command Error"])
        self.assertIsNone(result["name"])
        self.assertIn(
            "The model's name 'Command Error in Command Error' was rejected because it does not match"
            " the description.",
            err,
        )
        self.assertIn("may not clearly name a product and a flaw", err)
        self.assertNotIn("--model", err)

    def test_hint_for_a_cve_the_dataset_cannot_name(self):
        _, _, err = self.run_cli("CVE-2099-0001")
        self.assertIn("CVE-2099-0001 is not in the nightly dataset yet.", err)
        self.assertIn("Add --description", err)
        _, _, err = self.run_cli("CVE-2026-10000")
        self.assertIn("The nightly dataset has no name for CVE-2026-10000.", err)

    def test_rejects_bad_input(self):
        for argv, message in (
            (["SQL injection in AcmeShop"], "is not a CVE ID"),
            ([], "give a CVE ID"),
        ):
            with self.assertRaises(SystemExit) as raised:
                V.main(["name", *argv])
            self.assertIn(message, str(raised.exception))

    def test_offline_without_a_dataset_or_description_fails(self):
        with self.assertRaises(SystemExit) as raised:
            V.main(["name", "CVE-2026-1000", "--offline"])
        self.assertIn("cannot read the dataset", str(raised.exception))


class TestResolveLogging(unittest.TestCase):
    def logs(self, **kwargs):
        with self.assertLogs("vulnamer", "DEBUG") as captured:
            result = V.resolve_name(**kwargs)
        return result, "\n".join(captured.output)

    def test_reports_rejected_and_accepted_sources(self):
        result, output = self.logs(
            description=LOG4J_DESC,
            cve_id="CVE-2021-44228",
            nuclei_name="Vulnerability",
            kev_name="Apache Log4j2 Remote Code Execution Vulnerability",
        )
        self.assertEqual(result.source, "kev")
        self.assertIn("public name: 'Log4Shell' from the reviewed table", output)
        self.assertIn("nuclei: rejected 'Vulnerability'", output)
        self.assertIn("kev: accepted 'Apache Log4j2 Remote Code Execution'", output)
        self.assertNotIn("ghsa", output)  # stops at the first good name

    def test_one_line_when_no_titles_were_given(self):
        _, output = self.logs(description="Shell injection on Command Error")
        self.assertIn("nuclei, kev, ghsa, cna: no titles given", output)
        self.assertNotIn("nothing given", output)

    def test_reports_the_raw_model_output(self):
        _, output = self.logs(description=LOG4J_DESC, namer=FakeNamer("Apache Struts - Code Execution"))
        self.assertIn("model: rejected 'Apache Struts - Code Execution'", output)
        _, output = self.logs(description=LOG4J_DESC, namer=FakeNamer())
        self.assertIn("model: accepted 'Apache Log4j2 - Code Execution'", output)


LOG4J_EVIDENCE = {
    "nuclei_name": "Apache Log4j2 Remote Code Injection",
    "kev_name": "Apache Log4j2 Remote Code Execution Vulnerability",
    "ghsa_summary": "Remote code injection in Log4j",
    "cna_title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
}


class TestNameEachSource(unittest.TestCase):
    def test_one_source(self):
        results = V.name_each_source(LOG4J_DESC, sources=["kev"], **LOG4J_EVIDENCE)
        self.assertEqual(list(results), ["kev"])
        self.assertEqual(results["kev"].raw, "Apache Log4j2 Remote Code Execution Vulnerability")
        self.assertEqual(results["kev"].name, "Apache Log4j2 Remote Code Execution")

    def test_every_source_runs_and_keeps_the_order(self):
        namer = FakeNamer()
        results = V.name_each_source(LOG4J_DESC, namer=namer, **LOG4J_EVIDENCE)
        self.assertEqual(list(results), list(V.SOURCES))
        self.assertEqual(results["model"].name, "Apache Log4j2 - Code Execution")
        self.assertEqual(namer.calls, [LOG4J_DESC])  # runs even though nuclei already named it
        self.assertEqual(results["vendor"].note, "nothing found")

    def test_explains_what_is_missing(self):
        results = V.name_each_source(kev_name="Vulnerability", sources=["kev", "nuclei", "model"])
        self.assertEqual(results["kev"].note, "rejected by the checks")
        self.assertEqual(results["nuclei"].note, "no title")
        self.assertEqual(results["model"].note, "no description")
        self.assertEqual(V.name_each_source(LOG4J_DESC, sources=["model"])["model"].note, "model not loaded")

    def test_unknown_source(self):
        with self.assertRaises(ValueError):
            V.name_each_source(LOG4J_DESC, sources=["nvd"])

    def test_first_named_source_is_what_resolve_name_picks(self):
        prefix = "In the Linux kernel, the following vulnerability has been resolved:\n\n"
        cases = [
            dict(description=LOG4J_DESC, **LOG4J_EVIDENCE),
            dict(description=LOG4J_DESC, kev_name="Vulnerability", ghsa_summary="Remote code injection in Log4j"),
            dict(description="Foo Server has a buffer overflow, aka 'Foo Server Remote Code Execution'."),
            dict(description=prefix + "ovl: fix UAF in ovl_do_mkdir"),
            dict(description="Shell injection in AcmeShop 2.1.", namer=FakeNamer("Nope - Wrong Product")),
            dict(description="Shell injection on Command Error"),
        ]
        for case in cases:
            expected = V.resolve_name(**case)
            results = V.name_each_source(**case)
            winner = next((source for source in V.SOURCES if results[source].name), None)
            self.assertEqual((winner, winner and results[winner].name), (expected.source, expected.name))


class FakeFeeds:
    """Serves the live source URLs from memory and records what was requested."""

    def __init__(self, kev=None, nuclei=None, advisories=None, record=None):
        self.requested, self.headers = [], {}
        self.responses = {
            V.KEV_URL: json.dumps({"vulnerabilities": kev or []}),
            V.NUCLEI_CVES_URL: "\n".join(json.dumps(item) for item in nuclei or []),
            V.GHSA_API_URL.format(cve_id="CVE-2021-44228"): json.dumps(advisories or []),
        }
        if record:
            self.responses[V.CVE_RECORD_URL.format(cve_id="CVE-2021-44228")] = json.dumps(record)

    def __call__(self, url, headers=None):
        self.requested.append(url)
        self.headers[url] = headers or {}
        if url not in self.responses:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return self.responses[url].encode()


def log4j_feeds():
    return FakeFeeds(
        kev=[{"cveID": "CVE-2021-44228", "vulnerabilityName": LOG4J_EVIDENCE["kev_name"]}],
        nuclei=[{"ID": "CVE-2021-44228", "Info": {"Name": LOG4J_EVIDENCE["nuclei_name"]}}],
        advisories=[{"summary": "Vulnerability"}, {"summary": LOG4J_EVIDENCE["ghsa_summary"]}],
        record={
            "cveMetadata": {"state": "PUBLISHED", "cveId": "CVE-2021-44228"},
            "containers": {
                "cna": {
                    "title": LOG4J_EVIDENCE["cna_title"],
                    "descriptions": [{"lang": "en", "value": LOG4J_DESC}],
                }
            },
        },
    )


class TestFetchEvidence(unittest.TestCase):
    def fetch(self, feeds, sources=V.SOURCES, env=None):
        with mock.patch.object(V, "_http_get", feeds), mock.patch.dict(os.environ, env or {}, clear=True):
            return V.fetch_evidence("cve-2021-44228", sources)

    def test_fetches_every_source(self):
        evidence, errors = self.fetch(log4j_feeds())
        self.assertEqual(errors, {})
        self.assertEqual(
            evidence,
            {"description": LOG4J_DESC, **LOG4J_EVIDENCE},  # the usable advisory summary wins
        )

    def test_downloads_only_what_the_sources_need(self):
        feeds = log4j_feeds()
        self.fetch(feeds, ["kev"])
        self.assertEqual(feeds.requested, [V.KEV_URL])
        feeds = log4j_feeds()
        self.fetch(feeds, ["heuristic"])
        self.assertEqual(feeds.requested, [V.CVE_RECORD_URL.format(cve_id="CVE-2021-44228")])

    def test_asks_github_for_reviewed_advisories(self):
        self.assertIn("type=reviewed", V.GHSA_API_URL)
        feeds = log4j_feeds()
        self.fetch(feeds, ["ghsa"])
        self.assertIn(V.GHSA_API_URL.format(cve_id="CVE-2021-44228"), feeds.requested)

    def test_reports_what_could_not_be_fetched(self):
        evidence, errors = self.fetch(FakeFeeds(), ["cna", "kev"])
        self.assertEqual(errors, {"cve record": "not found"})
        self.assertNotIn("description", evidence)
        self.assertIsNone(evidence["kev_name"])


class TestSourceOption(unittest.TestCase):
    def run_cli(self, *argv, feeds=None, model_installed=False):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(V, "_http_get", feeds or log4j_feeds()), \
                mock.patch.object(V, "_download", side_effect=AssertionError("dataset used")), \
                mock.patch.object(V, "_model_installed", return_value=model_installed), \
                redirect_stdout(out), redirect_stderr(err):
            code = V.main(["name", *argv])
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_single_source(self):
        code, result, _ = self.run_cli("CVE-2021-44228", "--source", "kev")
        self.assertEqual(code, 0)
        self.assertEqual(
            result,
            {
                "id": "CVE-2021-44228",
                "name": "Apache Log4j2 Remote Code Execution",
                "source": "kev",
                "public_name": "Log4Shell",
                "sources": {
                    "kev": {
                        "raw": "Apache Log4j2 Remote Code Execution Vulnerability",
                        "name": "Apache Log4j2 Remote Code Execution",
                    }
                },
            },
        )

    def test_all_sources_pick_the_same_winner_as_the_naming_order(self):
        _, result, _ = self.run_cli("CVE-2021-44228", "-s", "all")
        self.assertEqual(list(result["sources"]), list(V.SOURCES))
        self.assertEqual(result["source"], "nuclei")
        self.assertEqual(result["sources"]["model"], {"note": 'install "vulnamer[model]" to run the model'})

    def test_runs_the_model_when_installed(self):
        fake = FakeNamer()
        with mock.patch.object(V.ModelNamer, "load", return_value=fake):
            _, result, _ = self.run_cli("CVE-2021-44228", "-s", "model", model_installed=True)
        self.assertEqual(result["source"], "model")
        self.assertEqual(fake.calls, [LOG4J_DESC])

    def test_comma_separated_sources(self):
        _, result, _ = self.run_cli("CVE-2021-44228", "-s", "heuristic, kev")
        self.assertEqual(list(result["sources"]), ["kev", "heuristic"])  # always in naming order

    def test_description_only(self):
        _, result, _ = self.run_cli("-d", "Shell injection in AcmeShop 2.1.", "-s", "kev,heuristic")
        self.assertEqual(result["sources"]["kev"], {"note": "needs a CVE ID"})
        self.assertEqual(result["name"], "AcmeShop - Command Injection")

    def test_unknown_cve_explains_each_source(self):
        _, result, _ = self.run_cli("CVE-2021-44228", "-s", "all", feeds=FakeFeeds())
        notes = {source: entry["note"] for source, entry in result["sources"].items()}
        self.assertEqual(notes["kev"], "not in the CISA KEV catalog")
        self.assertEqual(notes["ghsa"], "no GitHub-reviewed advisory")
        self.assertEqual(notes["cna"], "could not fetch the cve record: not found")
        self.assertEqual(notes["heuristic"], "no description, the cve record: not found")
        self.assertIsNone(result["name"])

    def test_verbose_reports_each_source(self):
        _, _, err = self.run_cli("CVE-2021-44228", "-s", "kev,vendor", "-v")
        self.assertIn("[vulnamer] kev: fetching", err)
        self.assertIn("[vulnamer] kev: Apache Log4j2 Remote Code Execution", err)
        self.assertIn("[vulnamer] vendor: nothing found", err)

    def test_rejects_bad_input(self):
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            V.main(["name", "CVE-2021-44228", "-s", "nvd"])
        with self.assertRaises(SystemExit) as raised:
            V.main(["name", "CVE-2021-44228", "-s", "kev", "--offline"])
        self.assertIn("cannot run with --offline", str(raised.exception))


class TestModelSetupErrors(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.dir = work.name

    def run_cli(self, *argv):
        with self.assertRaises(SystemExit) as raised, redirect_stdout(io.StringIO()):
            V.main(["name", "-d", "Shell injection on Command Error", *argv])
        return str(raised.exception)

    def test_directory_without_a_model(self):
        with self.assertRaises(FileNotFoundError) as raised:
            V.ModelNamer(self.dir)  # checked before onnxruntime is imported
        self.assertIn("missing encoder_model.onnx, decoder_model.onnx, tokenizer.json", str(raised.exception))
        message = self.run_cli("--model", self.dir)
        self.assertIn(f"no vulnamer model in {self.dir}", message)
        self.assertIn("Use --model on its own for the published model", message)
        self.assertIn(f"vulnamer download-model {self.dir}", message)

    def test_offline_without_a_cached_model(self):
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": self.dir}):
            message = self.run_cli("--model", "--offline")
        self.assertIn("Run once without --offline", message)

    def test_missing_model_extra(self):
        with mock.patch.object(V.ModelNamer, "load", side_effect=ImportError("No module named 'onnxruntime'")):
            message = self.run_cli("--model")
        self.assertIn('pip install "vulnamer[model]"', message)

    def test_failed_download(self):
        with mock.patch.object(V.ModelNamer, "load", side_effect=OSError("network is unreachable")):
            message = self.run_cli("--model")
        self.assertEqual(message, "vulnamer: could not download the model: network is unreachable")

    def test_source_option_reports_it_too(self):
        with mock.patch.object(V, "_http_get", log4j_feeds()), self.assertRaises(SystemExit) as raised:
            with redirect_stdout(io.StringIO()):
                V.main(["name", "CVE-2021-44228", "-s", "model", "--model", self.dir])
        self.assertIn("no vulnamer model in", str(raised.exception))


class TestModelDownload(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.archive = os.path.join(self.work.name, "model.tar.gz")
        with tarfile.open(self.archive, "w:gz") as tar:
            for name in (*V.MODEL_FILES, "../outside"):
                data = name.encode()
                info = tarfile.TarInfo(f"./{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.target = os.path.join(self.work.name, "cache", "model")
        self.downloads = 0

    def fake_download(self, url, directory):
        self.downloads += 1
        path = os.path.join(directory, "download")
        shutil.copyfile(self.archive, path)
        return path

    def download(self, checksum=None):
        checksum = checksum or V._sha256(self.archive)
        with mock.patch.object(V, "_download", self.fake_download):
            with mock.patch.object(V, "MODEL_SHA256", checksum):
                return V.download_model(self.target)

    def test_unpacks_only_the_model_files(self):
        self.assertEqual(self.download(), self.target)
        self.assertEqual(sorted(os.listdir(self.target)), sorted(V.MODEL_FILES))
        self.assertEqual(os.listdir(os.path.dirname(self.target)), ["model"])
        self.assertFalse(os.path.exists(os.path.join(self.work.name, "cache", "outside")))

    def test_second_call_does_not_download_again(self):
        self.download()
        self.download()
        self.assertEqual(self.downloads, 1)

    def test_a_bad_checksum_leaves_nothing_behind(self):
        with self.assertRaises(ValueError):
            self.download("0" * 64)
        self.assertEqual(os.listdir(os.path.dirname(self.target)), [])

    def test_cache_follows_xdg_cache_home(self):
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/somewhere"}):
            self.assertEqual(
                V.default_model_dir(), os.path.join("/somewhere", "vulnamer", V.MODEL_VERSION)
            )

    def test_published_model_checksum_is_pinned(self):
        self.assertRegex(V.MODEL_SHA256, r"^[0-9a-f]{64}$")
        self.assertIn(V.MODEL_VERSION, V.MODEL_URL)


@unittest.skipUnless(
    os.environ.get("VULNAMER_MODEL"), "set VULNAMER_MODEL to the exported model"
)
class TestRealModel(unittest.TestCase):
    """Runs the exported ONNX model. Needs the ``model`` extra."""

    @classmethod
    def setUpClass(cls):
        cls.namer = V.ModelNamer(os.environ["VULNAMER_MODEL"], threads=2)

    def test_names_descriptions_from_products_it_can_verify(self):
        descriptions = [
            "SQL injection in the login form of AcmeShop 2.1 allows remote attackers to read the database.",
            "Stored cross-site scripting in the\ncomment field of ZetaBoard before 4.0.",
        ]
        first, second = self.namer.name(descriptions)
        self.assertIn("AcmeShop", first)
        self.assertIn("SQL Injection", first)
        self.assertIn("ZetaBoard", second)
        self.assertIn("Cross-Site Scripting", second)

    def test_batching_does_not_change_the_output(self):
        description = "Path traversal in AcmeShop 2.1 allows reading arbitrary files."
        alone = self.namer.generate([description])[0]
        batched = self.namer.generate([description, "A much longer description. " * 30])[0]
        self.assertEqual(alone, batched)

    def test_a_name_does_not_depend_on_its_neighbours(self):
        # real descriptions whose name changed with the batch before each ran alone
        descriptions = [
            "A NULL pointer dereference (DoS) Vulnerability was found in the function "
            "aubio_source_avcodec_readframe in io/source_avcodec.c of aubio 0.4.6, which may "
            "lead to DoS when playing a crafted audio file.",
            "All versions of package realms-shim are vulnerable to Sandbox Bypass via a "
            "Prototype Pollution attack vector.",
            "nexkey is a microblogging platform. Insufficient validation of ActivityPub requests "
            "received in inbox could allow any user to impersonate another user in certain "
            "circumstances. This issue has been patched in version 12.122.2.",
        ]
        alone = [self.namer.generate([text])[0] for text in descriptions]
        filler = "Another description. " * 40
        together = [self.namer.generate([text, filler])[0] for text in descriptions]
        self.assertEqual(alone, together)

    def test_resolves_through_the_model_tier(self):
        result = V.resolve_name("SQL injection in AcmeShop 2.1 login.", namer=self.namer)
        self.assertEqual(result.source, "model")


class TestPackaging(unittest.TestCase):
    def test_exposes_a_version_and_the_dataset_location(self):
        self.assertRegex(V.__version__, r"^\d+\.\d+\.\d+")
        self.assertTrue(V.DATASET_URL.endswith("/vuln_names.jsonl.gz"))


class TestStandalone(unittest.TestCase):
    def test_only_imports_the_standard_library_at_module_level(self):
        import ast

        with open(V.__file__, encoding="utf-8") as source:
            tree = ast.parse(source.read())
        imported = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported, set(sys.stdlib_module_names))


if __name__ == "__main__":
    unittest.main()
