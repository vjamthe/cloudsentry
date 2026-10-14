import json, time, traceback
from datetime import datetime, timezone
import boto3
import app, sbom

inspector = boto3.client("inspector2")

def wait_for_scan(repo, digest, max_wait=600):
    """ECR push fires instantly; Inspector finishes a few minutes later. Poll until done."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        kw = {"filterCriteria": {"ecrRepositoryName": [{"comparison": "EQUALS", "value": repo}],
                                 "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}]}}
        while True:
            resp = inspector.list_coverage(**kw)
            for r in resp.get("coveredResources", []):
                if digest in r["resourceId"] and r.get("lastScannedAt") \
                   and r.get("scanStatus", {}).get("reason") == "SUCCESSFUL":
                    return True
            if not resp.get("nextToken"): break
            kw["nextToken"] = resp["nextToken"]
        time.sleep(20)
    return False

def count_findings(digest):
    n, token = 0, None
    while True:
        kw = {"filterCriteria": {"ecrImageHash": [{"comparison": "EQUALS", "value": digest}]}, "maxResults": 100}
        if token: kw["nextToken"] = token
        resp = inspector.list_findings(**kw)
        n += len(resp["findings"])
        token = resp.get("nextToken")
        if not token: return n

def wait_for_findings_to_settle(digest, interval=20, stable_checks=3, max_wait=180):
    """Inspector marks a scan SUCCESSFUL before all findings are queryable.
    Wait until the finding count is unchanged for `stable_checks` polls in a row."""
    deadline = time.time() + max_wait
    last, stable = -1, 0
    while time.time() < deadline:
        n = count_findings(digest)
        stable = stable + 1 if n == last else 0
        print(f"Findings so far: {n} (stable {stable}/{stable_checks})")
        if stable >= stable_checks - 1 and n > 0:
            return n
        last = n
        time.sleep(interval)
    print(f"Findings did not fully settle; proceeding with {last}")
    return last

def lambda_handler(event, context):
    if event.get("source") == "aws.ecr":
        d = event["detail"]
        repo, digest = d["repository-name"], d["image-digest"]
        tags = [d["image-tag"]] if d.get("image-tag") else []
        print(f"Push received: {repo}@{digest} tags={tags}, waiting for Inspector scan...")
        if not wait_for_scan(repo, digest):
            print(f"Timed out waiting for scan of {repo}@{digest}")
            return {"status": "scan_timeout"}
        wait_for_findings_to_settle(digest)
        event = {"source": "aws.inspector2", "detail": {
            "repository-name": f"arn:aws:ecr:{event['region']}:{event['account']}:repository/{repo}",
            "image-digest": digest, "image-tags": tags}}

    result = app.lambda_handler(event, context)
    try:
        d = event["detail"]
        arn = d["repository-name"]
        region, account = arn.split(":")[3], arn.split(":")[4]
        repo = arn.split(":repository/")[-1].split("/sha256:")[0]
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        result["sbom_verdict"] = sbom.analyze(f"{account}.dkr.ecr.{region}.amazonaws.com",
                                              repo, d["image-digest"], d.get("image-tags", []), ts)
    except Exception:
        traceback.print_exc()
        result["sbom_verdict"] = "ERROR"
    return result
