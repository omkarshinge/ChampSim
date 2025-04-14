import os
import json
import csv

base_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), "../results"))
output_csv = './results/final_stats/ipc.csv'

os.makedirs(os.path.dirname(output_csv), exist_ok=True)

data_rows = []

# Traverse all directories and subdirectories
for root, dirs, files in os.walk(base_directory):
    print(files)
    for file in files:
        if file.endswith('.json'):
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r') as f:
                    json_data = json.load(f)

                # Extract IPC value safely with detailed structure check
                ipc = json_data[0].get('roi', {}).get('cores', [{}])[0].get('ipc', None)

                if ipc is not None:
                    data_rows.append({'filename': file, 'ipc': ipc})
                    print(f"[SUCCESS] IPC {ipc} extracted from {file_path}")
                else:
                    print(f"[ERROR] 'ipc' field missing in {file_path}")

            except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
                print(f"[ERROR] Could not process {file_path}: {e}")

# # Write to CSV
with open(output_csv, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['filename', 'ipc'])
    writer.writeheader()
    writer.writerows(data_rows)

print(f"\nSuccessfully written IPC values to {output_csv}")
