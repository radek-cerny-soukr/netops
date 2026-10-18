import collections
import json
import pathlib
import re
import sys

EXPECTED = {
    "1": ["1.1.%d" % n for n in range(1, 19)] + ["1.2.1", "1.2.2"],
    "2": ["2.%d" % n for n in range(1, 19)],
    "3": ["3.%d" % n for n in range(1, 25)],
    "4": ["4.%d" % n for n in range(1, 13)],
    "5": ["5.%d" % n for n in range(1, 33)],
    "6": ["6.1", "6.2"],
    "7": ["7.%d" % n for n in range(1, 10)],
}

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def load(path):
    return json.loads(path.read_text(), object_pairs_hook=unique)

def check(out):
    image_text = (out / "cis-image-id.txt").read_text()
    cid_text = (out / "cis-container-id.txt").read_text()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}\n", image_text):
        raise ValueError("native image identity malformed")
    if not re.fullmatch(r"[0-9a-f]{64}\n", cid_text):
        raise ValueError("container identity malformed")
    image, cid = image_text.strip(), cid_text.strip()
    for when in ("before", "after"):
        inspect = load(out / ("cis-container-%s.json" % when))
        if not isinstance(inspect, list) or len(inspect) != 1:
            raise ValueError("container metadata malformed")
        item = inspect[0]
        state = item["State"]
        if item["Id"] != cid or item["Image"] != image:
            raise ValueError("running instance differs from inspected image/container")
        if state["Running"] is not True or state["OOMKilled"] is not False or state["Health"]["Status"] != "healthy":
            raise ValueError("instance is not running healthy without OOM")
    summary = {"meaning": "complete benchmark measurement; no compliance verdict", "reports": {}}
    for name, section_ids in (("cis-all", list(EXPECTED)), ("cis-netops", ["4", "5"])):
        report = load(out / (name + ".json"))
        if set(report) != {"dockerbenchsecurity", "start", "tests", "checks", "score", "end"}:
            raise ValueError("benchmark top-level shape differs")
        if report["dockerbenchsecurity"] != "1.6.0":
            raise ValueError("benchmark emitter version differs")
        if any(type(report[k]) is not int for k in ("start", "end", "checks", "score")):
            raise ValueError("benchmark counters/timestamps malformed")
        if not 0 < report["start"] <= report["end"] or abs(report["score"]) > report["checks"]:
            raise ValueError("benchmark counter/time range malformed")
        sections = report["tests"]
        if not isinstance(sections, list) or [s["id"] for s in sections] != section_ids:
            raise ValueError("benchmark sections incomplete")
        counts = collections.Counter()
        for section in sections:
            if set(section) != {"id", "desc", "results"} or not isinstance(section["desc"], str) or not section["desc"]:
                raise ValueError("section shape malformed")
            rows = section["results"]
            if not isinstance(rows, list) or [r["id"] for r in rows] != EXPECTED[section["id"]]:
                raise ValueError("benchmark check identities incomplete or duplicated")
            for row in rows:
                if not {"id", "desc", "result"} <= set(row) <= {"id", "desc", "result", "details", "items"}:
                    raise ValueError("check shape malformed")
                if not isinstance(row["desc"], str) or not row["desc"] or row["result"] not in {"PASS", "WARN", "NOTE", "INFO"}:
                    raise ValueError("check description/result malformed")
                if "details" in row and not isinstance(row["details"], str):
                    raise ValueError("check details malformed")
                if "items" in row and (not isinstance(row["items"], list) or not all(isinstance(x, str) for x in row["items"])):
                    raise ValueError("check items malformed")
                counts[row["result"]] += 1
        if report["checks"] != sum(counts.values()):
            raise ValueError("benchmark checks counter differs")
        summary["reports"][name] = {"counts": dict(sorted(counts.items())), "checks": report["checks"], "score": report["score"], "start": report["start"], "end": report["end"]}
    return summary

if __name__ == "__main__":
    try:
        print(json.dumps(check(pathlib.Path(sys.argv[1])), indent=2))
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
        print("CIS report integrity refused: %s" % error, file=sys.stderr)
        raise SystemExit(1)
