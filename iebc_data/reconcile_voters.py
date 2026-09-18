import os
import re
import sys
import time
import zipfile
import subprocess
import csv
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor, as_completed

BASE_DIR = '/home/steve/projects/laikipia/ol-kalou-backend/iebc_data'
EXCEL_PATH = os.path.join(BASE_DIR, 'Laikipia Combined.xlsx')
COUNTY_DIR = os.path.join(BASE_DIR, 'Laikipia County')
OUTPUT_CSV = os.path.join(BASE_DIR, 'laikipia_master_voters_2022.csv')

def clean_text(text):
    if not text:
        return ''
    # Remove leading numbers/hyphens if present e.g. "0811 - OL-MORAN" -> "OL-MORAN"
    t = re.sub(r'^\d+\s*-\s*', '', str(text).strip())
    return re.sub(r'\s+', ' ', t).strip().title()

def extract_pdf_voters(args):
    zip_path, pdf_rel_path = args
    voters = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            pdf_bytes = z.read(pdf_rel_path)
            
        proc = subprocess.Popen(
            ['pdftotext', '-layout', '-', '-'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, _ = proc.communicate(input=pdf_bytes)
        text = stdout.decode('utf-8', errors='ignore')
        
        county = 'Laikipia'
        constituency = ''
        ward = ''
        polling_centre = ''
        station_num = '01'
        
        # Single line search on the first page
        first_page = text.split('\x0c')[0] if '\x0c' in text else text[:2000]
        
        const_m = re.search(r'CONSTITUENCY\s*:\s*(?:[0-9]+\s*-\s*)?([^\r\n]+)', first_page)
        if const_m:
            constituency = clean_text(const_m.group(1))
            
        ward_m = re.search(r'COUNTY ASSEMBLY WARD\s*:\s*(?:[0-9]+\s*-\s*)?([^\r\n]+)', first_page)
        if ward_m:
            ward = clean_text(ward_m.group(1))
            
        centre_m = re.search(r'POLLING CENTRE\s*:\s*(?:[0-9]+\s*-\s*)?([^\r\n]+)', first_page)
        if centre_m:
            polling_centre = clean_text(centre_m.group(1))
            
        st_m = re.search(r'POLLING STATION\s*:\s*(\d+)', first_page)
        if st_m:
            station_num = st_m.group(1).strip()
            
        full_station_name = f"{polling_centre} (Station {station_num})" if station_num else polling_centre
        
        # Regex for voter lines:
        # Example: 001   ID   5*****3   BOSIRE   WILLIAM - ORECHI   1963   M   0045081212181257-3
        voter_pattern = re.compile(
            r'^\s*(\d{1,4})\s+(ID|PP|PASSPORT)\s+([0-9\*A-Z]+)\s+([A-Z\'\-\s]+?)\s{2,}([A-Z0-9\'\-\s]+?)\s{2,}(\d{4})\s+([MF])\s+([0-9A-Z\-]+)',
            re.MULTILINE
        )
        
        for m in voter_pattern.finditer(text):
            order = m.group(1).strip()
            id_type = m.group(2).strip()
            masked_id = m.group(3).strip()
            last_name = re.sub(r'\s+', ' ', m.group(4)).strip().upper()
            first_middle = re.sub(r'\s+', ' ', m.group(5)).strip().upper()
            yob = m.group(6).strip()
            sex = m.group(7).strip()
            electoral_no = m.group(8).strip()
            
            full_name = f"{first_middle} {last_name}".strip()
            
            voters.append({
                'order': order,
                'id_type': id_type,
                'masked_id': masked_id,
                'last_name': last_name,
                'first_middle': first_middle,
                'full_name': full_name,
                'yob': yob,
                'sex': sex,
                'electoral_no': electoral_no,
                'constituency': constituency,
                'ward': ward,
                'polling_station': full_station_name
            })
            
    except Exception as e:
        print(f"Error parsing {pdf_rel_path}: {e}", file=sys.stderr)
        
    return voters

def parse_all_2022_pdfs():
    print("=" * 60)
    print("STEP 1: Extracting voters from 2022 IEBC PDF files...")
    start_time = time.time()
    
    tasks = []
    zip_files = [
        '163 - Laikipia West.zip',
        '164 - Laikipia East.zip',
        '165 - Laikipia North.zip'
    ]
    
    for zname in zip_files:
        zpath = os.path.join(COUNTY_DIR, zname)
        if not os.path.exists(zpath):
            print(f"Warning: Zip not found: {zpath}")
            continue
        with zipfile.ZipFile(zpath, 'r') as z:
            for n in z.namelist():
                if n.lower().endswith('.pdf'):
                    tasks.append((zpath, n))
                    
    print(f"Found {len(tasks)} PDF files across all constituencies.")
    
    all_2022_voters = []
    workers = min(os.cpu_count() or 4, 16)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(extract_pdf_voters, t) for t in tasks]
        done_count = 0
        for future in as_completed(futures):
            res = future.result()
            all_2022_voters.extend(res)
            done_count += 1
            if done_count % 100 == 0 or done_count == len(tasks):
                print(f"  Processed {done_count}/{len(tasks)} PDFs ({len(all_2022_voters):,} voters extracted)...")
                
    elapsed = time.time() - start_time
    print(f"Extracted {len(all_2022_voters):,} total voters from 2022 PDFs in {elapsed:.1f}s.")
    return all_2022_voters

def load_and_index_2017_excel():
    print("\n" + "=" * 60)
    print("STEP 2: Streaming and Indexing 2017 Voter Dataset (Laikipia Combined.xlsx)...")
    start_time = time.time()
    
    index_by_name_yob_sex = {}
    total_2017_rows = 0
    
    with zipfile.ZipFile(EXCEL_PATH, 'r') as z:
        ss_list = []
        if 'xl/sharedStrings.xml' in z.namelist():
            tree = ET.iterparse(z.open('xl/sharedStrings.xml'))
            for event, elem in tree:
                if elem.tag.endswith('t'):
                    ss_list.append(elem.text if elem.text else '')
                    
        print(f"Loaded {len(ss_list):,} shared strings from Excel.")
        
        sheet_tree = ET.iterparse(z.open('xl/worksheets/sheet1.xml'), events=('end',))
        
        for event, elem in sheet_tree:
            if elem.tag.endswith('row'):
                total_2017_rows += 1
                if total_2017_rows == 1:
                    elem.clear()
                    continue
                    
                cells = []
                for c in elem.findall('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c'):
                    t = c.attrib.get('t')
                    v_tag = c.find('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}v')
                    val = v_tag.text if v_tag is not None else ''
                    if t == 's' and val.isdigit():
                        val = ss_list[int(val)]
                    cells.append(val)
                elem.clear()
                
                if len(cells) < 17:
                    continue
                    
                ward = clean_text(cells[5] if len(cells) > 5 else '')
                station = clean_text(cells[7] if len(cells) > 7 else '')
                dob_raw = str(cells[8] if len(cells) > 8 else '').strip()
                fname = re.sub(r'\s+', ' ', str(cells[9] if len(cells) > 9 else '')).strip().upper()
                mname = re.sub(r'\s+', ' ', str(cells[10] if len(cells) > 10 else '')).strip().upper()
                sname = re.sub(r'\s+', ' ', str(cells[11] if len(cells) > 11 else '')).strip().upper()
                sex = str(cells[12] if len(cells) > 12 else '').strip().upper()
                phone = str(cells[13] if len(cells) > 13 else '').strip()
                unmasked_id = str(cells[16] if len(cells) > 16 else '').strip()
                
                yob = ''
                yob_m = re.search(r'\b(19\d\d|20\d\d)\b', dob_raw)
                if yob_m:
                    yob = yob_m.group(1)
                    
                full_name = f"{fname} {mname} {sname}".strip()
                
                record = {
                    'unmasked_id': unmasked_id,
                    'phone': phone,
                    'dob': dob_raw.split(' ')[0] if ' ' in dob_raw else dob_raw,
                    'yob': yob,
                    'fname': fname,
                    'mname': mname,
                    'sname': sname,
                    'full_name': full_name,
                    'sex': sex,
                    'ward': ward,
                    'station': station
                }
                
                # Primary Index: (sname, fname, yob, sex)
                key1 = (sname, fname, yob, sex)
                if key1 not in index_by_name_yob_sex:
                    index_by_name_yob_sex[key1] = []
                index_by_name_yob_sex[key1].append(record)
                
                # Secondary Index with middle name
                if mname and mname != fname:
                    key2 = (sname, mname, yob, sex)
                    if key2 not in index_by_name_yob_sex:
                        index_by_name_yob_sex[key2] = []
                    index_by_name_yob_sex[key2].append(record)
                    
                if total_2017_rows % 50000 == 0:
                    print(f"  Indexed {total_2017_rows:,} 2017 records...")
                    
    elapsed = time.time() - start_time
    print(f"Indexed {total_2017_rows - 1:,} 2017 records into lookup table in {elapsed:.1f}s.")
    return index_by_name_yob_sex

def matches_masked_pattern(unmasked_id, masked_id):
    if not unmasked_id or not masked_id:
        return False
    if '*' in masked_id:
        if len(unmasked_id) != len(masked_id):
            return False
        if masked_id[0] != '*' and unmasked_id[0] != masked_id[0]:
            return False
        if masked_id[-1] != '*' and unmasked_id[-1] != masked_id[-1]:
            return False
        return True
    return unmasked_id == masked_id

def reconcile_and_export(voters_2022, index_2017):
    print("\n" + "=" * 60)
    print("STEP 3: Cross-referencing and Unmasking 2022 voters...")
    start_time = time.time()
    
    unmasked_count = 0
    phone_found_count = 0
    new_voters_count = 0
    
    master_records = []
    
    for v in voters_2022:
        last_name = v['last_name']
        first_middle = v['first_middle']
        yob = v['yob']
        sex = v['sex']
        masked_id = v['masked_id']
        
        first_tokens = [t for t in re.split(r'[\s\-]+', first_middle) if t]
        fname = first_tokens[0] if first_tokens else ''
        mname = first_tokens[1] if len(first_tokens) > 1 else ''
        
        matched_2017 = None
        
        # 1. Match on (last_name, fname, yob, sex)
        candidates = index_2017.get((last_name, fname, yob, sex), [])
        for cand in candidates:
            if matches_masked_pattern(cand['unmasked_id'], masked_id):
                matched_2017 = cand
                break
                
        # 2. Match on (last_name, mname, yob, sex)
        if not matched_2017 and mname:
            candidates = index_2017.get((last_name, mname, yob, sex), [])
            for cand in candidates:
                if matches_masked_pattern(cand['unmasked_id'], masked_id):
                    matched_2017 = cand
                    break
                    
        # 3. Match inverted name
        if not matched_2017 and fname:
            candidates = index_2017.get((fname, last_name, yob, sex), [])
            for cand in candidates:
                if matches_masked_pattern(cand['unmasked_id'], masked_id):
                    matched_2017 = cand
                    break

        if matched_2017:
            unmasked_id = matched_2017['unmasked_id']
            phone = matched_2017['phone']
            dob = matched_2017['dob']
            is_unmasked = True
            is_new = False
            unmasked_count += 1
            if phone:
                phone_found_count += 1
        else:
            unmasked_id = masked_id
            phone = ''
            dob = yob
            is_unmasked = False
            is_new = True
            new_voters_count += 1
            
        master_records.append({
            'id_number': unmasked_id,
            'phone_number': phone,
            'full_name': v['full_name'],
            'dob': dob,
            'gender': sex,
            'constituency': v['constituency'],
            'ward': v['ward'],
            'polling_station': v['polling_station'],
            'electoral_number': v['electoral_no'],
            'is_unmasked': '1' if is_unmasked else '0',
            'is_new_2022_voter': '1' if is_new else '0'
        })
        
    elapsed = time.time() - start_time
    total = len(master_records)
    print(f"Reconciliation completed in {elapsed:.1f}s.")
    print(f"Total 2022 Registered Voters: {total:,}")
    if total > 0:
        print(f"Successfully Unmasked National IDs: {unmasked_count:,} ({unmasked_count/total*100:.1f}%)")
        print(f"Direct Phone Numbers Attached: {phone_found_count:,} ({phone_found_count/total*100:.1f}%)")
        print(f"New 2017-2022 Registered Voters: {new_voters_count:,} ({new_voters_count/total*100:.1f}%)")
    
    print("\n" + "=" * 60)
    print(f"STEP 4: Writing Master CSV to {OUTPUT_CSV}...")
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'id_number', 'phone_number', 'full_name', 'dob', 'gender',
            'constituency', 'ward', 'polling_station', 'electoral_number',
            'is_unmasked', 'is_new_2022_voter'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(master_records)
        
    print(f"Saved {len(master_records):,} master voter records successfully ({os.path.getsize(OUTPUT_CSV)/(1024*1024):.2f} MB).")
    return master_records

if __name__ == '__main__':
    voters_2022 = parse_all_2022_pdfs()
    index_2017 = load_and_index_2017_excel()
    reconcile_and_export(voters_2022, index_2017)
