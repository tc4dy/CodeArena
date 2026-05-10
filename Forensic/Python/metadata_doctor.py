#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    import PyPDF2
    import git
except ImportError:
    print("[!] Install required: pip install Pillow PyPDF2 GitPython")
    sys.exit(1)

def extract_exif(img_path):
    """Extract EXIF data from image"""
    try:
        img = Image.open(img_path)
        exifdata = img._getexif()
        if not exifdata:
            return {}
        return {TAGS.get(k, k): v for k, v in exifdata.items()}
    except:
        return {}

def extract_pdf_metadata(pdf_path):
    """Extract PDF metadata"""
    try:
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            info = reader.metadata
            return {k[1:]: v for k, v in info.items()} if info else {}
    except:
        return {}

def extract_office_metadata(office_path):
    """Extract metadata from Office Open XML (docx, xlsx, pptx)"""
    if not zipfile.is_zipfile(office_path):
        return {}
    metadata = {}
    with zipfile.ZipFile(office_path, 'r') as zf:
        if 'docProps/core.xml' in zf.namelist():
            core = zf.read('docProps/core.xml')
            root = ET.fromstring(core)
            for elem in root.iter():
                if '}' in elem.tag:
                    tag = elem.tag.split('}')[1]
                    metadata[tag] = elem.text
        if 'docProps/app.xml' in zf.namelist():
            app = zf.read('docProps/app.xml')
            root = ET.fromstring(app)
            for elem in root.iter():
                if '}' in elem.tag:
                    tag = elem.tag.split('}')[1]
                    metadata[tag] = elem.text
    return metadata

def extract_git_metadata(repo_path):
    """Extract last commit, author, email, remotes"""
    try:
        repo = git.Repo(repo_path)
        head = repo.head.commit
        return {
            'last_commit': str(head),
            'author': head.author.name,
            'email': head.author.email,
            'committed_date': head.committed_datetime.isoformat(),
            'remotes': [r.url for r in repo.remotes]
        }
    except:
        return {}

def extract_ssh_metadata(file_path):
    """Extract comments from SSH keys"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        if 'ssh-rsa' in content or 'ssh-ed25519' in content:
            # Public key comment is usually at the end
            parts = content.split()
            if len(parts) >= 3:
                return {'comment': parts[2]}
    except:
        pass
    return {}

def main():
    parser = argparse.ArgumentParser(description='Metadata Doctor - Deep Metadata Extractor')
    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('--output', '-o', default='metadata_report.json', help='Output JSON file')
    parser.add_argument('--recursive', '-r', action='store_true', help='Recursively scan directories')
    args = parser.parse_args()

    results = {}
    target = Path(args.target)

    def process_file(fp):
        ext = fp.suffix.lower()
        meta = {}
        if ext in ['.jpg', '.jpeg', '.png', '.tiff']:
            meta['exif'] = extract_exif(fp)
        elif ext == '.pdf':
            meta['pdf'] = extract_pdf_metadata(fp)
        elif ext in ['.docx', '.xlsx', '.pptx']:
            meta['office'] = extract_office_metadata(fp)
        elif fp.name.endswith('.git'):
            meta['git'] = extract_git_metadata(fp)
        elif 'id_rsa' in fp.name or 'id_ed25519' in fp.name:
            meta['ssh'] = extract_ssh_metadata(fp)
        if meta:
            results[str(fp)] = meta

    if target.is_file():
        process_file(target)
    elif target.is_dir():
        if args.recursive:
            for root, dirs, files in os.walk(target):
                for f in files:
                    process_file(Path(root)/f)
        else:
            for f in target.iterdir():
                if f.is_file():
                    process_file(f)

    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] Metadata report saved to {args.output}")

if __name__ == '__main__':
    main()