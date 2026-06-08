# create_test_files.py
import os

folder = "test_folder"
os.makedirs(folder, exist_ok=True)

sample_contents = [
    "This is a confidential HR document.",
    "Q3 Financial Report: Revenue $1.2M",
    "Patient record: John Doe, DOB 1990-01-01",
    "Project blueprint for new product launch.",
    "Employee payroll data for October 2024.",
    "Source code backup: main.c version 3.2",
    "Legal agreement draft between parties.",
    "Marketing strategy for 2025 Q1 campaign.",
]

for i, content in enumerate(sample_contents):
    filepath = os.path.join(folder, f"document_{i+1}.txt")
    with open(filepath, "w") as f:
        f.write(content)

print(f"[+] Created {len(sample_contents)} dummy files in '{folder}/'")
