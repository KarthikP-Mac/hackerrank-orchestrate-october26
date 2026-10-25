content = open(r'code\main.py', encoding='utf-8').read()
# Find the bad line and replace
bad = "cur.execute(f\"SELECT * FROM \\\"{table}\\\" WHERE {\\' OR \\'.join(conds)}\", params)"
good = "where_clause = \" OR \".join(conds)\n                    cur.execute(f\"SELECT * FROM \\\"{table}\\\" WHERE {where_clause}\", params)"
if bad in content:
    new_content = content.replace(bad, good, 1)
    open(r'code\main.py', 'w', encoding='utf-8').write(new_content)
    print("Fixed!")
else:
    # Try alternate approach - just find and fix line 421
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'SELECT * FROM' in line and "join(conds)" in line:
            indent = '                    '
            lines[i] = f'{indent}where_clause = " OR ".join(conds)\n{indent}cur.execute(f\'SELECT * FROM "{{table}}" WHERE {{where_clause}}\', params)'
            print(f"Fixed line {i+1}")
            break
    open(r'code\main.py', 'w', encoding='utf-8').write('\n'.join(lines))
    print("Done via line replacement")
