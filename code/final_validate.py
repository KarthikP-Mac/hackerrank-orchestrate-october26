import csv, json

rows = list(csv.DictReader(open('output.csv', newline='', encoding='utf-8')))
print('Rows:', len(rows))
print('Header:', list(rows[0].keys()))

errors = 0
for r in rows:
    cid = r['case_id']
    try:
        steps = json.loads(r['steps_json'])
        for i, s in enumerate(steps):
            expected_no = i + 1
            if s['step_no'] != expected_no:
                print(f'step_no mismatch in {cid}: expected {expected_no} got {s["step_no"]}')
                errors += 1
    except Exception as e:
        errors += 1
        print(f'Error in {cid}: {e}')

if errors == 0:
    print('All steps_json valid!')
print(f'JSON errors: {errors}')
print('First row:', rows[0]['case_id'], rows[0]['deletion_status'])
print('Last row:', rows[-1]['case_id'], rows[-1]['deletion_status'])

# Status distribution
from collections import Counter
dist = Counter(r['deletion_status'] for r in rows)
print('Distribution:', dict(dist))
