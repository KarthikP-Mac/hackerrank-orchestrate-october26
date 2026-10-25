"""Deep validation: compare sample outputs and fix empty steps issue."""
import csv, json

def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# Check if sample cases are in deletion_requests.csv
del_req = {r["case_id"] for r in load_csv("dataset/deletion_requests.csv")}
sample_req = [r["case_id"] for r in load_csv("dataset/sample_deletion_requests.csv")]
sample_out = {r["case_id"]: r for r in load_csv("dataset/sample_output.csv")}

print("Sample cases in deletion_requests.csv:", [c for c in sample_req if c in del_req])
print("Sample cases NOT in deletion_requests.csv:", [c for c in sample_req if c not in del_req])

output = {r["case_id"]: r for r in load_csv("output.csv")}

# Find empty steps COMPLETE cases
empty_cases = [(cid, row) for cid, row in output.items()
               if row["deletion_status"] == "COMPLETE" and json.loads(row["steps_json"]) == []]
print(f"\nCOMPLETE cases with empty steps: {len(empty_cases)}")
print("First 10:", [c[0] for c in empty_cases[:10]])
