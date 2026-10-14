import os, json, csv, gzip, math
from datetime import datetime, timezone
from decimal import Decimal
import boto3, joblib, numpy as np

inspector = boto3.client("inspector2")
s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
BUCKET = os.environ["BUCKET_NAME"]

# Load model + NVD feature lookup once per container (cold start)
bundle = joblib.load("/var/task/cve_model.joblib")
MODEL, COLS = bundle["model"], bundle["columns"]
IDX = {c: i for i, c in enumerate(COLS)}
NVD = {}
with gzip.open("/var/task/nvd_features.csv.gz", "rt") as f:
    for r in csv.DictReader(f):
        NVD[r.pop("cve")] = r

CAT = ["attack_vector","attack_complexity","privileges","user_interaction","scope","conf","integ","avail","cwe"]
NUM = ["base_score","exploitability","impact","n_refs","has_exploit_ref","has_patch_ref"]
LVL = {"N":"NONE","L":"LOW","H":"HIGH"}
VEC = {"AV": ("attack_vector", {"N":"NETWORK","A":"ADJACENT_NETWORK","L":"LOCAL","P":"PHYSICAL"}),
       "AC": ("attack_complexity", {"L":"LOW","H":"HIGH"}),
       "PR": ("privileges", LVL), "UI": ("user_interaction", {"N":"NONE","R":"REQUIRED"}),
       "S": ("scope", {"U":"UNCHANGED","C":"CHANGED"}),
       "C": ("conf", LVL), "I": ("integ", LVL), "A": ("avail", LVL)}

def to_num(v):
    if isinstance(v, bool): return float(v)
    if v in ("True", "False"): return float(v == "True")
    try: return float(v)
    except (TypeError, ValueError): return math.nan

def from_inspector(f):
    """Fallback for CVEs not in our NVD snapshot: use Inspector's own data."""
    vuln = f.get("packageVulnerabilityDetails", {})
    r = {"n_refs": len(vuln.get("referenceUrls", [])),
         "has_exploit_ref": f.get("exploitAvailable") == "YES",
         "has_patch_ref": f.get("fixAvailable") == "YES"}
    for c in vuln.get("cvss", []):
        if str(c.get("version", "")).startswith("3"):
            r["base_score"] = c.get("baseScore")
            for part in c.get("scoringVector", "").split("/")[1:]:
                k, _, v = part.partition(":")
                if k in VEC:
                    r[VEC[k][0]] = VEC[k][1].get(v)
            break
    return r

def features(cve, finding):
    r = NVD.get(cve) or from_inspector(finding)
    x = np.zeros(len(COLS))
    for c in NUM:
        if c in IDX: x[IDX[c]] = to_num(r.get(c))
    for c in CAT:
        col = f"{c}_{r.get(c)}"
        if col in IDX: x[IDX[col]] = 1.0
    return x, cve in NVD

def get_findings(digest):
    findings, token = [], None
    while True:
        kw = {"filterCriteria": {"ecrImageHash": [{"comparison": "EQUALS", "value": digest}]}, "maxResults": 100}
        if token: kw["nextToken"] = token
        resp = inspector.list_findings(**kw)
        findings += resp["findings"]
        token = resp.get("nextToken")
        if not token: return findings

def lambda_handler(event, context):
    print(json.dumps(event))
    d = event["detail"]
    digest = d["image-digest"]
    repo = d["repository-name"].split(":repository/")[-1].split("/sha256:")[0]
    tags = d.get("image-tags", [])
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    findings = get_findings(digest)
    cves = [f.get("packageVulnerabilityDetails", {}).get("vulnerabilityId", "N/A") for f in findings]

    scores, in_nvd = [], []
    if findings:
        feats = [features(c, f) for c, f in zip(cves, findings)]
        X = np.vstack([x for x, _ in feats])
        scores = MODEL.predict_proba(X)[:, 1]
        in_nvd = [n for _, n in feats]

    key = f"raw/{repo}/{digest.replace(':', '_')}/{ts}.json"
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(findings, default=str))

    with table.batch_writer() as batch:
        for f, cve, s, n in zip(findings, cves, scores, in_nvd):
            pkgs = f.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [{}])
            batch.put_item(Item={
                "image_digest": digest,
                "finding_id": f["findingArn"].split("/")[-1],
                "repo": repo, "tags": tags, "cve": cve,
                "severity": f.get("severity", "UNKNOWN"),
                "inspector_score": Decimal(str(f.get("inspectorScore", 0))),
                "exploit_score": Decimal(str(round(float(s), 4))),
                "features_source": "nvd" if n else "inspector_fallback",
                "package": pkgs[0].get("name", "N/A"),
                "package_version": pkgs[0].get("version", "N/A"),
                "fix_available": f.get("fixAvailable", "UNKNOWN"),
                "scanned_at": ts,
            })

    top = sorted(zip(cves, scores), key=lambda t: -t[1])[:5]
    print(f"{repo}@{digest}: {len(findings)} findings scored. Top: {[(c, round(float(s), 3)) for c, s in top]}")
    return {"findings": len(findings), "s3_key": key}
