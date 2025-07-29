import os
import gzip
import re
import sys
import concurrent.futures
from typing import Tuple

# Verhoeff tables for Aadhaar validation
mult = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
]
perm = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8]
]

def Validate(aadharNum: str) -> str:
    """
    Run the Verhoeff checksum on a 12-digit string.
    Returns 'Valid' or 'Invalid'.
    """
    try:
        x = 0
        j = 0
        for digit in reversed(aadharNum):
            x = mult[x][perm[j % 8][int(digit)]]
            j += 1
        return 'Valid' if x == 0 else 'Invalid'
    except (ValueError, IndexError):
        return 'Invalid'

# PII patterns, including Aadhaar and keyword-based checks
PII_PATTERNS = {
    "AADHAAR_REGEX": re.compile(r'\b[0-9]{12}\b'),
    "DL_REGEX": re.compile(r'[A-Z]{2}[0-9]{2}[\-\s]?[0-9]{4}[0-9]{7}'),
    "GSTIN_REGEX": re.compile(r'[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]Z[A-Z0-9]'),
    "IP_REGEX": re.compile(r'([0-9]{1,3}\.){3}[0-9]{1,3}'),
    "MAC_REGEX": re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'),
    "COORD_REGEX": re.compile(r'-?[0-9]{1,3}\.[0-9]+,\s*-?[0-9]{1,3}\.[0-9]+'),
    "EMAIL_REGEX": re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    "MOBILE_REGEX": re.compile(r'(\+91|91|0)?[6-9][0-9]{9}'),
    "PAN_REGEX": re.compile(r'[A-Z]{5}[0-9]{4}[A-Z]'),
    "UPI_REGEX": re.compile(r'[A-Za-z0-9]+@[A-Za-z]+'),
    "VOTERID_REGEX": re.compile(r'[A-Z]{3}[0-9]{7}'),
    "CARD_REGEX": re.compile(
        r'4[0-9]{12}(?:[0-9]{3})?'
        r'|5[1-5][0-9]{14}'
        r'|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7(?:[01][0-9]{12}|20[0-9]{12}))'
        r'|3[47][0-9]{13}'
        r'|60[0-9]{14}'
        r'|65[0-9]{14}'
        r'|81[0-9]{14}'
        r'|508[0-9][0-9]{12}'
    ),
    # Keyword-based patterns
    "ADDRESS_KEYWORD": re.compile(
        r'\b(address|full address|complete address|residential address|permanent address|locality|pincode|postal code|zip|zip code|city|state|add)\b',
        re.IGNORECASE
    ),
    "NAME_KEYWORD": re.compile(r'\b(name|nam)\b', re.IGNORECASE),
    "DOB_KEYWORD": re.compile(r'\b(date of birth|dob|birthdate|born on)\b', re.IGNORECASE),
    "ACCOUNT_NUMBER_KEYWORD": re.compile(r'\b(account number|acc number|bank account|account no|a/c no)\b', re.IGNORECASE),
    "CUSTOMER_ID_KEYWORD": re.compile(r'\b(customer id|cust id|customer number|cust)\b', re.IGNORECASE),
    "SENSITIVE_HINTS_KEYWORD": re.compile(r'\b(national id|identity card|proof of identity|document number)\b', re.IGNORECASE),
    "INSURANCE_POLICY_KEYWORD": re.compile(r'\b(insurance number|policy number|insurance id|ins id)\b', re.IGNORECASE),
}

# Global counters for summary
total_files_parsed = 0
total_lines_parsed = 0
total_lines_with_pii = 0

def process_gz_file(gz_file_path: str, output_dir: str) -> Tuple[int,int,int]:
    """
    Process one .gz: scan for PII (including Aadhaar + validation),
    write matches to a .txt in the mirrored output_dir.
    """
    file_lines_processed = 0
    file_lines_with_pii = 0

    os.makedirs(output_dir, exist_ok=True)
    out_name = os.path.basename(gz_file_path).replace('.gz', '.txt')
    out_path = os.path.join(output_dir, out_name)

    with gzip.open(gz_file_path, 'rt', encoding='utf-8', errors='ignore') as infile, \
         open(out_path, 'w', encoding='utf-8') as outfile:

        for line in infile:
            file_lines_processed += 1
            clean = line.strip()
            matches = []

            for ptype, pattern in PII_PATTERNS.items():
                for m in pattern.finditer(clean):
                    val = m.group(0)
                    start = m.start()
                    # Look up to 4 chars before for fieldName=
                    prefix = clean[max(0, start-4):start]
                    fm = re.search(r'(\b\w+\b)\s*=$', prefix)
                    field = fm.group(1) if fm else 'no_field'

                    if ptype == 'AADHAAR_REGEX':
                        # Validate Aadhaar
                        validation = Validate(val)
                        matches.append((field, val, ptype, validation))
                    else:
                        matches.append((field, val, ptype))

            if matches:
                file_lines_with_pii += 1
                parts = [clean]
                for entry in matches:
                    parts.extend(entry)
                outfile.write(';'.join(parts) + '\n')

    return 1, file_lines_processed, file_lines_with_pii

def scan_for_pii_in_folder(input_folder: str):
    """
    Walk the directory, process .gz files in parallel,
    print a summary, and write an indicator file.
    """
    global total_files_parsed, total_lines_parsed, total_lines_with_pii

    if not os.path.isdir(input_folder):
        print(f"Error: '{input_folder}' is not a directory.", file=sys.stderr)
        return

    base = os.path.basename(os.path.normpath(input_folder))
    root_out = os.path.join("path_processed", base)
    os.makedirs(root_out, exist_ok=True)
    print(f"Output will be under: {os.path.abspath(root_out)}")

    tasks = []
    for dirpath, _, files in os.walk(input_folder):
        rel = os.path.relpath(dirpath, input_folder)
        outdir = os.path.join(root_out, rel)
        for f in files:
            if f.endswith('.gz'):
                tasks.append((os.path.join(dirpath, f), outdir))

    local_f = local_l = local_p = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_gz_file, p, o): p for p, o in tasks}
        for fut in concurrent.futures.as_completed(futures):
            path = futures[fut]
            try:
                fc, lc, pc = fut.result()
                local_f += fc
                local_l += lc
                local_p += pc
                print(f"Processed: {path}")
            except Exception as e:
                print(f"Error on {path}: {e}", file=sys.stderr)

    total_files_parsed = local_f
    total_lines_parsed = local_l
    total_lines_with_pii = local_p

    summary = (
        "--- PII Scan Summary ---\n"
        f"Total files parsed: {total_files_parsed}\n"
        f"Total lines parsed: {total_lines_parsed}\n"
        f"Total lines containing PII: {total_lines_with_pii}\n"
        "------------------------"
    )
    banner = (
        "\n========================================\n"
        "||             SCAN COMPLETE!         ||\n"
        "||             ALL DONE!              ||\n"
        "========================================\n"
    )
    print(f"\n{summary}")
    print(banner)

    # Indicator file
    indicator = f"{base}_all_done.txt"
    try:
        with open(indicator, 'w', encoding='utf-8') as f:
            f.write(summary + banner)
        print(f"Indicator file created: {indicator}")
    except Exception as e:
        print(f"Error writing indicator file '{indicator}': {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pii_scanner.py <folder_with_gz_files>")
    else:
        scan_for_pii_in_folder(sys.argv[1])
