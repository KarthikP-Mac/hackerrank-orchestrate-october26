"""Validate output.csv against sample_output.csv"""
import csv, json

def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return {r["case_id"]: r for r in csv.DictReader(f)}

output = load_csv("output.csv")
sample = load_csv("dataset/sample_output.csv")

print(f"Output rows: {len(output)}")
print(f"Sample rows: {len(sample)}")

# Check all sample cases
correct_status = 0
wrong_status = 0
for cid, srow in sorted(sample.items()):
    if cid not in output:
        print(f"MISSING: {cid}")
        continue
    orow = output[cid]
    expected_status = srow["deletion_status"]
    got_status = orow["deletion_status"]
    if expected_status == got_status:
        correct_status += 1
    else:
        print(f"WRONG STATUS {cid}: expected={expected_status} got={got_status}")
        wrong_status += 1

print(f"\nStatus accuracy: {correct_status}/{len(sample)} = {correct_status/len(sample)*100:.1f}%")
print(f"Wrong status: {wrong_status}")

# Check steps JSON validity
invalid_json = 0
empty_steps_deletion = 0
for cid, row in output.items():
    try:
        steps = json.loads(row["steps_json"])
        if row["deletion_status"] != "NOT_APPLICABLE" and len(steps) == 0:
            empty_steps_deletion += 1
            if empty_steps_deletion <= 5:
                print(f"EMPTY STEPS: {cid} status={row['deletion_status']}")
    except Exception as e:
        invalid_json += 1
        print(f"INVALID JSON {cid}: {e}")

print(f"\nInvalid JSON: {invalid_json}")
print(f"Empty steps (non-N/A): {empty_steps_deletion}")

# Status distribution
statuses = {}
for row in output.values():
    s = row["deletion_status"]
    statuses[s] = statuses.get(s, 0) + 1
print(f"\nDistribution: {statuses}")
