import os, json, math, base64, subprocess
from decimal import Decimal
import boto3, joblib, numpy as np

s3, ecr = boto3.client("s3"), boto3.client("ecr")
table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
BUCKET = os.environ["BUCKET_NAME"]

M = joblib.load("/var/task/sbom_model.joblib")
ISO, COLS, THR, GFREQ = M["model"], M["cols"], M["threshold"], M["gfreq"]
OFFENSIVE, POPULAR = set(M["offensive"]), set(M["popular"])
KNOWN_LEGIT, REGISTRY_TYPES = set(M["known_legit"]), set(M["registry_types"])

def lev1(a, b):
    if a == b or abs(len(a) - len(b)) > 1: return False
    if len(a) == len(b): return sum(x != y for x, y in zip(a, b)) == 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i+1:] == s for i in range(len(l)))

def run_syft(registry, repo, digest):
    tok = ecr.get_authorization_token()["authorizationData"][0]["authorizationToken"]
    user, pwd = base64.b64decode(tok).decode().split(":", 1)
    env = {**os.environ, "HOME": "/tmp", "TMPDIR": "/tmp", "SYFT_CHECK_FOR_APP_UPDATE": "false",
           "SYFT_REGISTRY_AUTH_AUTHORITY": registry,
           "SYFT_REGISTRY_AUTH_USERNAME": user, "SYFT_REGISTRY_AUTH_PASSWORD": pwd}
    out = subprocess.run(["/usr/local/bin/syft", f"registry:{registry}/{repo}@{digest}", "-o", "syft-json", "-q"],
                         env=env, capture_output=True, text=True, timeout=600, check=True).stdout
    return [[a.get("name", "").lower(), a.get("type", ""), a.get("version", ""), bool(a.get("licenses"))]
            for a in json.loads(out)["artifacts"]]

def drift(prev, new):  # must match training exactly
    p = {(t, n): (v, l) for n, t, v, l in prev}
    q = {(t, n): (v, l) for n, t, v, l in new}
    added = [k for k in q if k not in p]
    removed = [k for k in p if k not in q]
    a = max(len(added), 1)
    return {
        "log_added": math.log1p(len(added)),
        "log_removed": math.log1p(len(removed)),
        "frac_added": len(added) / max(len(p), 1),
        "size_log_ratio": math.log((len(q) + 1) / (len(p) + 1)),
        "n_new_ecosystems": len({t for t, _ in q} - {t for t, _ in p}),
        "added_no_license": sum(1 for k in added if not q[k][1]) / a,
        "added_no_version": sum(1 for k in added if not q[k][0]) / a,
        "added_binary": sum(1 for k in added if k[0] == "binary") / a,
        "added_rare": sum(1 for k in added if GFREQ.get(k, 0) == 0) / a,
    }

def analyze(registry, repo, digest, tags, ts):
    pkgs = run_syft(registry, repo, digest)
    names = {n for n, *_ in pkgs}
    reg = {n for n, t, *_ in pkgs if t in REGISTRY_TYPES}
    offensive = sorted(names & OFFENSIVE)
    typos = sorted(n for n in reg if len(n) >= 5 and n not in POPULAR and n not in KNOWN_LEGIT
                   and any(lev1(n, p) for p in POPULAR))

    key = f"sbom/{repo}/latest.json"
    try:
        prev = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    except s3.exceptions.NoSuchKey:
        prev = None

    score, f = None, None
    if prev is not None:
        f = drift(prev, pkgs)
        score = float(-ISO.score_samples(np.array([[f[c] for c in COLS]]))[0])

    if offensive or typos:
        verdict = "BLOCK"
    elif score is not None and score > THR:
        verdict = "REVIEW"
    else:
        verdict = "PASS"

    s3.put_object(Bucket=BUCKET, Key=f"sbom/{repo}/{digest.replace(':', '_')}.json", Body=json.dumps(pkgs))
    if verdict == "PASS":  # only clean builds become the new baseline
        s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(pkgs))

    item = {"image_digest": digest, "finding_id": "SBOM_ANALYSIS", "repo": repo, "tags": tags,
            "verdict": verdict, "n_packages": len(pkgs), "offensive_tools": offensive,
            "typosquats": typos, "has_baseline": prev is not None, "scanned_at": ts}
    if score is not None:
        item["anomaly_score"] = Decimal(str(round(score, 4)))
        item["threshold"] = Decimal(str(round(THR, 4)))
        item["drift"] = {k: Decimal(str(round(v, 4))) for k, v in f.items()}
    table.put_item(Item=item)
    print(f"SBOM {repo}@{digest[:19]}: {len(pkgs)} pkgs | verdict={verdict} | score={score} | "
          f"offensive={offensive} typos={typos}")
    return verdict
