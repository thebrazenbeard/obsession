"""Fetch public, exact-commit dependency source exports; verify Git blob hashes.

Run explicitly before the candidate. This utility never installs a package or
changes an existing source file. Review the checked-in lock before using it.
"""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import re


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    lock = json.loads((Path(__file__).parent / "dependency-lock.json").read_text())
    for name, subject in lock.items():
        if subject["repo"] not in {"thebrazenbeard/pre-active", "thebrazenbeard/obsession"} or not re.fullmatch("[0-9a-f]{40}",subject["head"]):
            raise ValueError("unexpected dependency subject")
        base = args.directory.resolve() / ("pre-active" if name == "pre_active" else "obsession")
        for item in subject["files"]:
            target = (base / item["path"]).resolve()
            if not target.is_relative_to(base) or not re.fullmatch(r"[A-Za-z0-9_./-]+",item["path"]):
                raise ValueError("dependency path escaped root")
            if target.exists():
                data = target.read_bytes()
            else:
                conn = http.client.HTTPSConnection("raw.githubusercontent.com",timeout=20)
                try:
                    conn.request("GET","/"+subject["repo"]+"/"+subject["head"]+"/"+item["path"])
                    response = conn.getresponse()
                    if response.status != 200:
                        raise RuntimeError("dependency fetch rejected; no redirects followed")
                    data = response.read(500001)
                finally:
                    conn.close()
                if len(data) > 500000:
                    raise ValueError("dependency file over size budget")
            actual = hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
            if actual != item["sha"]:
                raise ValueError("dependency blob mismatch: "+item["path"])
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as output:
                    output.write(data)
    print(json.dumps({"status":"VERIFIED_SOURCE_EXPORTS","heads":{k:v["head"] for k,v in lock.items()}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
