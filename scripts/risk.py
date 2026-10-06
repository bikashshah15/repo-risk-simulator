#!/usr/bin/env python3
"""Hosted GitHub SBOM + OSV + offline scenarios. Python standard library only."""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib import error, parse, request

VERSION = "1.1.0"
ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "gem": "RubyGems",
              "golang": "Go", "cargo": "crates.io", "nuget": "NuGet",
              "composer": "Packagist", "hex": "Hex", "pub": "Pub"}
ROOT = Path(__file__).resolve().parents[1]
EGRESS_HINT = ("Required HTTPS hosts: api.github.com, api.osv.dev, and GitHub's SBOM download host "
               "(the fetch-report redirect target, e.g. *.blob.core.windows.net or *.githubusercontent.com).")


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True).encode()
    return hashlib.sha256(value).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


class APIError(RuntimeError):
    pass


def network_message(host, exc):
    """Sanitized network error; flags a likely proxy/egress refusal without echoing URLs."""
    reason = str(getattr(exc, "reason", exc)).lower()
    if "tunnel connection failed" in reason or "proxy" in reason:
        return ("Connection to %s was refused by a proxy; an egress allowlist may block this host. %s"
                % (host, EGRESS_HINT))
    return "Network request failed for %s; check connectivity or egress policy. %s" % (host, EGRESS_HINT)


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def allowed_url(url):
    p = parse.urlsplit(url)
    host = p.hostname or ""
    if p.scheme != "https" or p.username or p.password or p.port not in (None, 443):
        return False
    return (host in {"api.github.com", "api.osv.dev", "raw.githubusercontent.com",
                     "objects.githubusercontent.com", "github.com"}
            or host.endswith(".githubusercontent.com") or host.endswith(".blob.core.windows.net"))


def http(url, payload=None, limit=24 * 1024 * 1024):
    """Bounded HTTPS. Rebuild headers at redirects so credentials never cross hosts."""
    opener = request.build_opener(NoRedirect())
    method = "POST" if payload is not None else "GET"
    body = json.dumps(payload).encode() if payload is not None else None
    for _redirect in range(6):
        if not allowed_url(url):
            raise APIError("Endpoint/redirect host is not allowed; review provider documentation.")
        host = parse.urlsplit(url).hostname
        headers = {"Accept": "application/json", "User-Agent": "repo-risk-simulator/" + VERSION}
        if host == "api.github.com":
            headers["X-GitHub-Api-Version"] = os.environ.get("GITHUB_API_VERSION", "2026-03-10")
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
        if body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(3):
            try:
                with opener.open(request.Request(url, data=body, headers=headers, method=method), timeout=25) as r:
                    content = r.read(limit + 1)
                    if len(content) > limit:
                        raise APIError("Response exceeds the configured size limit.")
                    return r.status, content
            except error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    target = e.headers.get("Location")
                    if not target:
                        raise APIError("Redirect has no target.") from None
                    url = parse.urljoin(url, target)
                    if e.code in (301, 302, 303):
                        method, body = "GET", None
                    break
                if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(min(3, 1 + attempt))
                    continue
                raise APIError("HTTP %d from %s; check access, availability, or rate limits." % (e.code, host)) from None
            except (error.URLError, TimeoutError, OSError) as exc:
                if attempt < 2:
                    time.sleep(1)
                    continue
                raise APIError(network_message(host, exc)) from None
        else:
            raise APIError("Retry budget exhausted.")
    raise APIError("Redirect budget exhausted.")


def probe(url):
    """Reachability only: any HTTP response (even 4xx) means the host is reachable."""
    host = parse.urlsplit(url).hostname
    opener = request.build_opener(NoRedirect())
    try:
        with opener.open(request.Request(url, headers={"User-Agent": "repo-risk-simulator/" + VERSION}), timeout=15) as r:
            return {"host": host, "reachable": True, "http_status": r.status}
    except error.HTTPError as e:
        return {"host": host, "reachable": True, "http_status": e.code}
    except (error.URLError, TimeoutError, OSError) as exc:
        return {"host": host, "reachable": False, "error": network_message(host, exc)}


def preflight(args):
    checks = [probe("https://api.github.com/"),
              probe("https://api.osv.dev/v1/vulns/REPO-RISK-PREFLIGHT")]
    blocked = [c["host"] for c in checks if not c["reachable"]]
    print(json.dumps({"checks": checks, "ready": not blocked,
                      "note": "GitHub chooses the SBOM download host at export time; collect/fetch report it if blocked."}, indent=2))
    return 1 if blocked else 0


def api(url, payload=None):
    status, content = http(url, payload)
    if not content and status == 202:
        return status, None
    try:
        return status, json.loads(content)
    except (ValueError, UnicodeDecodeError):
        raise APIError("API response is not JSON.") from None


def repo_name(value):
    if value.startswith("https://"):
        p = parse.urlsplit(value)
        if p.hostname != "github.com" or p.query or p.fragment or p.username or p.password:
            raise ValueError("Use https://github.com/OWNER/REPO or OWNER/REPO.")
        value = p.path.strip("/")
    value = value.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("Use a GitHub repository URL or OWNER/REPO.")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("Invalid GitHub owner/repository name.")
    return value


def path_ok(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or ".." in p.parts or "\\" in value:
        raise ValueError("Use a relative repository file path without traversal.")
    return value


def package_query(purl, version):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, "Missing Package URL; package identity is unresolved."
    if "?" in purl or "#" in purl:
        return None, "Qualified/subpath Package URLs require identity review."
    body = purl[4:]
    if "/" not in body:
        return None, "Invalid Package URL."
    typ, coordinate = body.split("/", 1)
    if typ not in ECOSYSTEMS:
        return None, "Unsupported ecosystem: " + typ
    if "@" in coordinate:
        coordinate, pv = coordinate.rsplit("@", 1)
        pv = parse.unquote(pv)
        if version and version != "NOASSERTION" and pv != version:
            return None, "SPDX and Package URL versions disagree."
        version = pv
    if not isinstance(version, str) or not version or version in ("NOASSERTION", "UNKNOWN"):
        return None, "Exact version is missing."
    if re.search(r"[\s<>=*|~^]", version):
        return None, "Version is a range or unresolved expression."
    name = parse.unquote(coordinate)
    if not name:
        return None, "Package name is missing."
    if typ == "maven":
        if "/" not in name:
            return None, "Maven group/artifact identity is incomplete."
        group, artifact = name.rsplit("/", 1)
        name = group + ":" + artifact
    return {"package": {"name": name, "ecosystem": ECOSYSTEMS[typ]}, "version": version}, None


def normalize(document):
    document = document.get("sbom", document)
    if not str(document.get("spdxVersion", "")).startswith("SPDX-") or not isinstance(document.get("packages"), list):
        raise ValueError("Expected an SPDX JSON document with packages.")
    packages, evidence = [], []
    doc_id = document.get("SPDXID", "SPDXRef-DOCUMENT")
    roots = {r.get("relatedSpdxElement") for r in document.get("relationships", []) or []
             if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == doc_id}
    roots |= set(document.get("documentDescribes", []) or [])
    for index, p in enumerate(document["packages"]):
        purls = sorted(set(r.get("referenceLocator", "") for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"))
        purl = purls[0] if len(purls) == 1 else None
        version = p.get("versionInfo")
        query, reason = package_query(purl, version)
        if len(purls) > 1:
            reason = "Multiple Package URLs require identity review."
        is_root = p.get("SPDXID") in roots
        if is_root:
            query, reason = None, "SBOM root (the analyzed repository itself); not a dependency, so it is not queried."
        pid = "P%04d" % (index + 1)
        if query:
            version = query["version"]
        item = {"id": pid, "spdx_id": p.get("SPDXID"), "name": p.get("name", "Unknown"),
                "version": version, "purl": purl, "query": query,
                "status": "root" if is_root else ("pending" if query else "unsupported"), "reason": reason,
                "advisory_ids": [], "evidence_id": "PKG-" + pid}
        packages.append(item)
        evidence.append({"id": item["evidence_id"], "kind": "package", "package_id": pid,
                         "location": "sbom.json#" + str(p.get("SPDXID", index)),
                         "excerpt": json.dumps({"name": item["name"], "version": version, "purl": purl}),
                         "sha256": digest(p)})
    return document, packages, evidence


def collect(args):
    out = Path(args.out).resolve()
    if (out / "run.json").exists():
        raise ValueError("Output already has a run; use fetch/lookup or choose a new folder.")
    name = repo_name(args.repo)
    base = "https://api.github.com/repos/" + name
    _, meta = api(base)
    name = repo_name(meta.get("full_name", name))
    base = "https://api.github.com/repos/" + name
    ref = args.ref or meta["default_branch"]
    _, commit = api(base + "/commits/" + parse.quote(ref, safe=""))
    state = {"schema_version": 1, "tool_version": VERSION, "collected_at": now(),
             "repository": {"name": name, "url": "https://github.com/" + name,
                            "default_branch": meta["default_branch"], "requested_ref": ref,
                            "source_commit": commit["sha"], "private": bool(meta.get("private")),
                            "alignment": "unverified"},
             "sbom_status": "pending", "packages": [], "findings": [], "evidence": [],
             "warnings": ["GitHub's dependency graph export cannot establish exact correspondence with the source commit."]}
    save(out / "run.json", state)
    if args.sbom:
        store_sbom(out, state, read(args.sbom))
        source = (getattr(args, "sbom_source", None) or "user-supplied file")[:300]
        state["sbom_provenance"] = {"method": "supplied_file", "source": source,
                                    "retrieved_at": getattr(args, "sbom_retrieved_at", None),
                                    "file_sha256": digest(Path(args.sbom).read_bytes()), "ingested_at": now()}
        state["warnings"].append("SBOM was supplied via --sbom (source: %s); correspondence and freshness are unverified." % source)
        check_head(state)
        save(out / "run.json", state)
        return summarize(state)
    try:
        _, job = api(base + "/dependency-graph/sbom/generate-report")
        fetch_url = job.get("sbom_url", "")
        if not fetch_url.lower().startswith(base.lower() + "/dependency-graph/sbom/fetch-report/"):
            raise APIError("Generation response has no valid repository fetch URL.")
        state["sbom_fetch_url"] = fetch_url
        save(out / "run.json", state)
        fetch_run(out, state, args.polls)
    except APIError as exc:
        state["sbom_status"] = "error"
        state["sbom_error"] = str(exc)
        save(out / "run.json", state)
        raise
    summarize(state)


def store_sbom(out, state, document):
    document, packages, evidence = normalize(document)
    save(out / "sbom.json", document)
    state.update(sbom_status="ready", packages=packages, evidence=evidence,
                 sbom_sha256=digest(document), sbom_created=document.get("creationInfo", {}).get("created"))
    state.pop("sbom_error", None)
    if not any(p["status"] != "root" for p in packages):
        warning = ("GitHub's dependency graph lists no dependencies (only the repository root, if any). Check for missing "
                   "manifests/lockfiles or a disabled dependency graph; this is not a clean result.")
        if warning not in state["warnings"]:
            state["warnings"].append(warning)


def fetch_run(out, state, polls):
    if state["sbom_status"] == "ready":
        return
    fetch_url = state.get("sbom_fetch_url")
    if not fetch_url:
        raise APIError("No resumable SBOM job; review collection error.")
    for index in range(polls):
        status, doc = api(fetch_url)
        if status == 202:
            if index + 1 < polls:
                time.sleep(2)
            continue
        store_sbom(out, state, doc)
        state["sbom_provenance"] = {"method": "github_async_export", "retrieved_at": now()}
        break
    if state["sbom_status"] == "ready":
        check_head(state)
    save(out / "run.json", state)


def check_head(state):
    """Record the default-branch head after SBOM acquisition; supports, never proves, alignment."""
    repo = state["repository"]
    try:
        _, c = api("https://api.github.com/repos/" + repo["name"] + "/commits/" + parse.quote(repo["default_branch"], safe=""))
        repo["head_after_export"] = c["sha"]
        repo["head_checked_at"] = now()
        if c["sha"] != repo["source_commit"]:
            state["warnings"].append("Default branch head differs from source commit; snapshot mismatch is possible.")
    except APIError:
        state["warnings"].append("Could not check default branch after export.")


def fetch(args):
    out = Path(args.run)
    state = read(out / "run.json")
    fetch_run(out, state, args.polls)
    summarize(state)


def batch_matches(queries):
    result = [set() for _ in queries]
    pending = [(i, dict(q)) for i, q in enumerate(queries)]
    for _page in range(20):
        _, data = api("https://api.osv.dev/v1/querybatch", {"queries": [q for _, q in pending]})
        rows = data.get("results")
        if not isinstance(rows, list) or len(rows) != len(pending):
            raise APIError("OSV batch response count does not match query count.")
        follow = []
        for (index, query), row in zip(pending, rows):
            result[index].update(v["id"] for v in row.get("vulns", []))
            if row.get("next_page_token"):
                follow.append((index, dict(query, page_token=row["next_page_token"])))
        if not follow:
            return [sorted(ids) for ids in result]
        pending = follow
    raise APIError("OSV pagination budget exceeded; queries are incomplete.")


def alias_groups(records):
    groups = []
    for record in records:
        names = {record["id"], *record.get("aliases", [])}
        merged = [record]
        remaining = []
        for ids, rows in groups:
            if names & ids:
                names |= ids
                merged.extend(rows)
            else:
                remaining.append((ids, rows))
        # New union may bridge earlier groups.
        changed = True
        while changed:
            changed = False
            retained = []
            for ids, rows in remaining:
                if names & ids:
                    names |= ids
                    merged.extend(rows)
                    changed = True
                else:
                    retained.append((ids, rows))
            remaining = retained
        groups = remaining + [(names, merged)]
    return groups


def lookup(args):
    out = Path(args.run)
    state = read(out / "run.json")
    if state["sbom_status"] != "ready":
        raise ValueError("SBOM is not ready; complete fetch before lookup.")
    cachepath = out / "osv_cache.json"
    cache = read(cachepath) if cachepath.exists() else {}
    todo = [p for p in state["packages"] if p["query"] and
            (args.refresh or p["status"] not in ("matched", "no_match"))]
    stats = {"queryable_packages": sum(bool(p["query"]) for p in state["packages"]),
             "queries_attempted": 0, "query_errors": 0, "records_fetched": 0, "records_from_cache": 0}
    for start in range(0, len(todo), 50):
        chunk = todo[start:start + 50]
        stats["queries_attempted"] += len(chunk)
        try:
            ids = batch_matches([p["query"] for p in chunk])
            for p, matched in zip(chunk, ids):
                p.update(advisory_ids=matched, queried_at=now(), query_sha256=digest(p["query"]),
                         status="matched" if matched else "no_match", reason=None)
        except APIError as exc:
            stats["query_errors"] += len(chunk)
            for p in chunk:
                p.update(status="error", reason=str(exc), queried_at=now(), advisory_ids=[])
    state["evidence"] = [e for e in state["evidence"] if e["kind"] != "advisory"]
    state["findings"] = []
    for p in state["packages"]:
        if p["status"] not in ("matched", "no_match"):
            continue
        records, errors, withdrawn = [], [], []
        for vid in p["advisory_ids"]:
            try:
                if args.refresh or vid not in cache:
                    _, record = api("https://api.osv.dev/v1/vulns/" + parse.quote(vid, safe=""))
                    if record.get("id") != vid:
                        raise APIError("OSV full record identity mismatch.")
                    cache[vid] = {"retrieved_at": now(), "record": record}
                    stats["records_fetched"] += 1
                else:
                    stats["records_from_cache"] += 1
                record = cache[vid]["record"]
                if record.get("withdrawn"):
                    withdrawn.append(vid)
                    continue
                records.append(record)
                eid = "ADV-" + vid
                if not any(e["id"] == eid for e in state["evidence"]):
                    state["evidence"].append({"id": eid, "kind": "advisory", "advisory_id": vid,
                         "location": "https://osv.dev/" + parse.quote(vid, safe=""),
                         "excerpt": (record.get("summary", "") + "\n" + record.get("details", ""))[:18000],
                         "sha256": digest(record), "retrieved_at": cache[vid]["retrieved_at"]})
            except APIError as exc:
                errors.append({"id": vid, "error": str(exc)})
        p["withdrawn_ids"], p["record_errors"] = withdrawn, errors
        if errors:
            p["status"] = "error"
            p["reason"] = "One or more full advisory records could not be retrieved."
        elif not records:
            p["status"] = "no_match"
        for aliases, rows in alias_groups(records):
            vids = sorted({r["id"] for r in rows})
            fid = "F-" + digest([p["id"], vids])[:12]
            severity = [s for r in rows for s in r.get("severity", [])]
            state["findings"].append({"id": fid, "package_id": p["id"], "advisory_ids": vids,
                    "aliases": sorted(aliases), "summary": next((r["summary"] for r in rows if r.get("summary")), vids[0]),
                    "severity": severity, "evidence_ids": [p["evidence_id"]] + ["ADV-" + v for v in vids],
                    "records_complete": not errors})
    state["lookup_at"] = now()
    state["osv"] = stats
    save(cachepath, cache)
    save(out / "run.json", state)
    summarize(state)


def tree(args):
    out = Path(args.run)
    state = read(out / "run.json")
    repo = state["repository"]
    _, doc = api("https://api.github.com/repos/" + repo["name"] + "/git/trees/" + repo["source_commit"] + "?recursive=1")
    paths = [x["path"] for x in doc.get("tree", []) if x.get("type") == "blob"]
    save(out / "tree.json", {"commit": repo["source_commit"], "truncated": bool(doc.get("truncated")), "paths": paths})
    print(json.dumps({"saved": "tree.json", "file_count": len(paths), "truncated": bool(doc.get("truncated")), "paths": paths[:400]}, indent=2))


def source(args):
    out = Path(args.run)
    state = read(out / "run.json")
    repo = state["repository"]
    path = out / "source.json"
    files = read(path) if path.exists() else {}
    if len(args.path) > 12:
        raise ValueError("Fetch at most 12 source files per command.")
    for name in args.path:
        path_ok(name)
        _, item = api("https://api.github.com/repos/" + repo["name"] + "/contents/" + parse.quote(name, safe="/") + "?ref=" + repo["source_commit"])
        if not isinstance(item, dict) or item.get("type") != "file" or item.get("encoding") != "base64" or item.get("size", 0) > 262144:
            raise ValueError("Source must be a regular text file of at most 256 KiB.")
        content = base64.b64decode(item["content"])
        if len(content) > 262144 or b"\x00" in content:
            raise ValueError("Source is binary or too large.")
        text = content.decode("utf-8")
        files[name] = {"commit": repo["source_commit"], "sha256": digest(content), "text": text}
        save(path, files)
    print(json.dumps({"saved": "source.json", "paths": args.path}))


def evidence(args):
    out = Path(args.run)
    state, files = read(out / "run.json"), read(out / "source.json")
    path_ok(args.path)
    file = files[args.path]
    lines = file["text"].splitlines()
    if not 1 <= args.start <= args.end <= len(lines) or args.end - args.start >= 80:
        raise ValueError("Evidence must be 1–80 valid source lines.")
    excerpt = "\n".join(lines[args.start - 1:args.end])
    if len(excerpt) > 12000:
        raise ValueError("Evidence excerpt is too large.")
    eid = "SRC-" + digest([args.path, args.start, args.end, file["sha256"]])[:12]
    entry = {"id": eid, "kind": "source", "location": args.path, "start": args.start, "end": args.end,
             "commit": file["commit"], "sha256": file["sha256"], "excerpt": excerpt}
    state["evidence"] = [e for e in state["evidence"] if e["id"] != eid] + [entry]
    save(out / "run.json", state)
    print(json.dumps(entry, indent=2))


def init_analysis(args):
    out = Path(args.run)
    if (out / "analysis.json").exists():
        raise ValueError("analysis.json exists; edit it instead of overwriting.")
    save(out / "analysis.json", {"schema_version": 1, "selection_notes": "Draft: review findings and cite evidence before adding scenarios.",
        "limitations": ["Static analysis does not establish deployment exposure or exploitability."],
        "assessments": [], "scenarios": []})
    print("Created analysis.json; Claude must review evidence and draft the analysis.")


def contract(value, schema, location="analysis"):
    """Validate the JSON Schema subset used by the bundled contract, without packages."""
    def fail(message):
        raise ValueError(location + ": " + message)
    kind = schema.get("type")
    types = {"object": lambda x: type(x) is dict, "array": lambda x: type(x) is list,
             "string": lambda x: type(x) is str, "boolean": lambda x: type(x) is bool,
             "integer": lambda x: type(x) is int}
    if kind and not types[kind](value):
        fail("expected " + kind)
    def equal(a, b):
        return type(a) is type(b) and a == b
    if "const" in schema and not equal(value, schema["const"]):
        fail("invalid constant")
    if "enum" in schema and not any(equal(value, option) for option in schema["enum"]):
        fail("invalid enumerated value")
    if type(value) is dict:
        missing = set(schema.get("required", [])) - set(value)
        if missing:
            fail("missing fields: " + ", ".join(sorted(missing)))
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            fail("unexpected fields: " + ", ".join(sorted(set(value) - set(properties))))
        for key, item in value.items():
            if key in properties:
                contract(item, properties[key], location + "." + key)
    if type(value) is list:
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            fail("invalid item count")
        for index, item in enumerate(value):
            contract(item, schema.get("items", {}), location + "[%d]" % index)
    if type(value) is str:
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            fail("invalid string length")


def validated(out):
    state, analysis = read(out / "run.json"), read(out / "analysis.json")
    contract(analysis, read(ROOT / "references/analysis.schema.json"))
    def check(test, message):
        if not test:
            raise ValueError(message)
    def string(value):
        return isinstance(value, str) and bool(value.strip()) and len(value) <= 18000
    check(analysis.get("schema_version") == 1, "Unsupported analysis schema_version.")
    check(string(analysis.get("selection_notes")), "selection_notes is required.")
    check(isinstance(analysis.get("limitations"), list) and analysis["limitations"] and all(map(string, analysis["limitations"])), "Global limitations are required.")
    evid = {e["id"]: e for e in state["evidence"]}
    check(len(evid) == len(state["evidence"]), "Duplicate evidence IDs.")
    findings = {f["id"]: f for f in state["findings"]}
    def refs(value, required=False):
        check(isinstance(value, list) and (bool(value) or not required) and all(isinstance(v, str) and v in evid for v in value), "Invalid or missing evidence_ids.")
    notes = analysis.get("context_notes", [])
    check(isinstance(notes, list), "context_notes must be a list.")
    for note in notes:
        check(isinstance(note, dict) and string(note.get("text")), "Context note text is required.")
        refs(note.get("evidence_ids"), True)
    sourcepath = out / "source.json"
    sources = read(sourcepath) if sourcepath.exists() else {}
    for e in evid.values():
        if e["kind"] == "source":
            file = sources.get(e["location"])
            check(file is not None, "Source evidence file is missing.")
            check(file["commit"] == e["commit"] == state["repository"]["source_commit"], "Source evidence commit mismatch.")
            check(digest(file["text"].encode()) == file["sha256"] == e["sha256"], "Source evidence hash mismatch.")
            lines = file["text"].splitlines()
            check(1 <= e["start"] <= e["end"] <= len(lines), "Invalid source evidence line range.")
            check("\n".join(lines[e["start"] - 1:e["end"]]) == e["excerpt"], "Source excerpt mismatch.")
    assessments = analysis.get("assessments")
    scenarios = analysis.get("scenarios")
    check(isinstance(assessments, list), "assessments must be a list.")
    check(isinstance(scenarios, list) and len(scenarios) <= 3, "Use zero to three scenarios.")
    seen = set()
    for a in assessments:
        fid = a.get("finding_id")
        check(fid in findings and fid not in seen, "Unknown or duplicate assessment finding.")
        seen.add(fid)
        check(a.get("status") in ("unknown", "potentially_applicable", "ruled_out_under_evidence"), "Invalid assessment status.")
        check(string(a.get("rationale")) and isinstance(a.get("limitations"), list) and a["limitations"] and all(map(string, a["limitations"])), "Assessment rationale/limitations required.")
        refs(a.get("evidence_ids"), True)
        check(set(findings[fid]["evidence_ids"]) <= set(a["evidence_ids"]), "Assessment must include finding evidence.")
        if a["status"] != "unknown":
            check(any(evid[x]["kind"] == "source" for x in a["evidence_ids"]), "Non-unknown assessment requires source evidence.")
    sids, sfids = set(), set()
    for s in scenarios:
        fid = s.get("finding_id")
        check(fid in findings and fid not in sfids, "Scenarios need distinct known findings.")
        sfids.add(fid)
        check(string(s.get("id")) and s["id"] not in sids, "Scenario ID is missing or duplicated.")
        sids.add(s["id"])
        for key in ("title", "hypothetical_impact", "application_evidence_gap"):
            check(string(s.get(key)), "Scenario requires " + key)
        refs(s.get("evidence_ids"), True)
        check(set(findings[fid]["evidence_ids"]) <= set(s["evidence_ids"]), "Scenario must include all finding evidence.")
        for key in ("assumptions", "unknowns", "limitations"):
            check(isinstance(s.get(key), list) and all(map(string, s[key])) and (s[key] or key != "limitations"), "Invalid scenario " + key)
        check(isinstance(s.get("facts"), list), "facts must be a list.")
        for fact in s["facts"]:
            check(string(fact.get("text")), "Fact text is required.")
            refs(fact.get("evidence_ids"), True)
            check(set(fact["evidence_ids"]) <= set(s["evidence_ids"]), "Fact evidence must belong to scenario.")
        controls = s.get("prerequisites")
        check(isinstance(controls, list) and 1 <= len(controls) <= 8, "Use 1–8 prerequisites.")
        pids = set()
        for p in controls:
            check(string(p.get("id")) and p["id"] not in pids, "Duplicate/missing prerequisite ID.")
            pids.add(p["id"])
            check(string(p.get("label")) and string(p.get("explanation")), "Prerequisite label/explanation required.")
            check(type(p.get("required_value")) is bool, "required_value must be Boolean.")
            check(p.get("initial") in ("true", "false", "unknown"), "Invalid initial value.")
            check(p.get("basis") in ("observed", "assumption"), "Invalid prerequisite basis.")
            refs(p.get("evidence_ids"), p["basis"] == "observed")
            check(set(p["evidence_ids"]) <= set(s["evidence_ids"]), "Control evidence must belong to scenario.")
            if p["basis"] == "assumption":
                check(p["initial"] == "unknown", "Assumptions must start unknown.")
        steps = s.get("steps")
        check(isinstance(steps, list) and 2 <= len(steps) <= 8, "Use 2–8 hypothetical steps.")
        for step in steps:
            check(string(step.get("text")), "Step text is required.")
            refs(step.get("evidence_ids"))
            check(set(step["evidence_ids"]) <= set(s["evidence_ids"]), "Step evidence must belong to scenario.")
    return state, analysis


def evaluate(controls, values):
    """Same three-valued semantics as the offline template; known blockers dominate."""
    if any(values[p["id"]] != "unknown" and (values[p["id"]] == "true") != p["required_value"] for p in controls):
        return "blocked"
    if any(values[p["id"]] == "unknown" for p in controls):
        return "unknown"
    return "satisfied"


def render(args):
    out = Path(args.run)
    state, analysis = validated(out)
    payload = {"run": state, "analysis": analysis}
    safe = json.dumps(payload, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = (ROOT / "assets/report.html").read_text(encoding="utf-8")
    if template.count("__REPORT_DATA__") != 1:
        raise ValueError("Invalid report template.")
    result = template.replace("__REPORT_DATA__", safe)
    (out / "report.html").write_text(result, encoding="utf-8")
    print(json.dumps({"report": str((out / "report.html").resolve()), "scenarios": len(analysis["scenarios"]), "validation": "passed"}))


def summarize(state):
    counts = {s: sum(p["status"] == s for p in state["packages"]) for s in ("pending", "matched", "no_match", "unsupported", "error", "root")}
    print(json.dumps({"repository": state["repository"]["name"], "sbom_status": state["sbom_status"],
          "packages": len(state["packages"]), "dependencies": len(state["packages"]) - counts["root"],
          "query_statuses": counts, "osv": state.get("osv"),
          "findings": len(state["findings"]), "alignment": state["repository"]["alignment"],
          "warnings": state["warnings"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    c = subs.add_parser("collect")
    c.add_argument("--repo", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--ref")
    c.add_argument("--sbom")
    c.add_argument("--sbom-source", help="Where the --sbom file came from (provenance label).")
    c.add_argument("--sbom-retrieved-at", help="UTC timestamp when the --sbom file was retrieved.")
    c.add_argument("--polls", type=int, default=6)
    subs.add_parser("preflight")
    for name in ("fetch", "lookup", "tree", "source", "evidence", "init-analysis", "validate", "render"):
        sub = subs.add_parser(name)
        sub.add_argument("--run", required=True)
        if name == "fetch":
            sub.add_argument("--polls", type=int, default=6)
        if name == "lookup":
            sub.add_argument("--refresh", action="store_true")
        if name == "source":
            sub.add_argument("--path", action="append", required=True)
        if name == "evidence":
            sub.add_argument("--path", required=True)
            sub.add_argument("--start", type=int, required=True)
            sub.add_argument("--end", type=int, required=True)
    args = parser.parse_args()
    try:
        if hasattr(args, "polls") and not 1 <= args.polls <= 12:
            raise ValueError("Poll budget must be 1–12.")
        if args.command == "collect" and not args.sbom and (args.sbom_source or args.sbom_retrieved_at):
            raise ValueError("--sbom-source/--sbom-retrieved-at require --sbom.")
        if args.command == "validate":
            validated(Path(args.run))
            print("Analysis and evidence validation passed.")
        else:
            return globals()[args.command.replace("-", "_")](args) or 0
    except (APIError, ValueError, KeyError, OSError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
