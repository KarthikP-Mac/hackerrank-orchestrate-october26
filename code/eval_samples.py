"""Run sample cases through our solution and compare with sample_output.csv"""
import csv, json, sys
sys.path.insert(0, 'code')

def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# Import our solution modules
import importlib.util
spec = importlib.util.spec_from_file_location("main", "code/main.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

rules = {r["data_category"]: r["required_action"] for r in load_csv("dataset/deletion_rules.csv")}
identities = {r["user_id"]: r for r in load_csv("dataset/user_identities.csv")}
audit_log = load_csv("dataset/user_audit_log.csv")
manifest = load_csv("dataset/evidence_files.csv")
sql_manifest = [e for e in manifest if e["file_path"].endswith(".sql")]

store = m.EvidenceStore(manifest)
store.build_index()

sample_cases = load_csv("dataset/sample_deletion_requests.csv")
sample_expected = {r["case_id"]: r for r in load_csv("dataset/sample_output.csv")}

correct = 0
wrong = 0
empty_steps = 0
for case in sample_cases:
    result = m.process_case(case, identities, audit_log, store, sql_manifest, rules)
    cid = case["case_id"]
    expected = sample_expected.get(cid, {})
    got_status = result["deletion_status"]
    exp_status = expected.get("deletion_status", "?")
    steps = json.loads(result["steps_json"])
    
    status_ok = got_status == exp_status
    if status_ok:
        correct += 1
    else:
        wrong += 1
        print(f"WRONG {cid}: expected={exp_status} got={got_status}")
    
    if got_status != "NOT_APPLICABLE" and len(steps) == 0:
        empty_steps += 1
        print(f"  EMPTY STEPS: {cid} status={got_status}")

print(f"\nStatus accuracy: {correct}/{len(sample_cases)} = {correct/len(sample_cases)*100:.1f}%")
print(f"Wrong: {wrong}, Empty steps: {empty_steps}")
