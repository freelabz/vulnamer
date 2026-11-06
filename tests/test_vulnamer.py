import gzip
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
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

    def test_curated_name_that_stopped_applying_reaches_the_model(self):
        description = "Foo has an odd flaw."
        previous = {
            "CVE-1": {
                "name": "Foo Advisory Title",
                "source": "ghsa",
                "description_hash": V.description_hash(description),
            }
        }
        namer = FakeNamer("Foo - Odd Flaw")
        rows = list(V.build_dataset([("CVE-1", description, "")], {}, {}, {}, {}, namer, previous))
        self.assertEqual(namer.calls, [description])
        self.assertEqual(rows[0]["source"], "model")

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

    def test_reused_name_the_guard_now_rejects_is_dropped(self):
        previous = {
            "CVE-1": {
                "name": "Invented Product - Odd Flaw",
                "source": "model",
                "description_hash": V.description_hash("Foo has an odd flaw."),
            }
        }
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, FakeNamer(), previous))
        self.assertIsNone(rows[0]["name"])

    def test_changed_description_runs_the_model_again(self):
        namer = FakeNamer("Foo - Odd Flaw")
        previous = {"CVE-1": {"name": "Old", "source": "model", "description_hash": "0"}}
        rows = list(V.build_dataset(self.RECORDS[:1], {}, {}, {}, {}, namer, previous))
        self.assertEqual(rows[0]["name"], "Foo - Odd Flaw")
        self.assertEqual(len(namer.calls), 1)

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
        self.assertEqual(rows[0]["name"], "MySQL Server - Denial of Service")
        self.assertEqual(namer.calls, [])


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


@unittest.skipUnless(
    os.environ.get("VULNAMER_MODEL"), "set VULNAMER_MODEL to the exported model"
)
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
