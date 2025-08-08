import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from ttkthemes import ThemedTk
import os
import time
import hashlib
import exifread
import PyPDF2
import docx
import platform

try:
    import magic  # Untuk deteksi file type
except ImportError:
    magic = None  # Tangani nanti

def extract_metadata(file_path):
    ext = os.path.splitext(file_path)[-1].lower()
    metadata = {}

    try:
        if ext in ['.jpg', '.jpeg']:
            with open(file_path, 'rb') as img_file:
                tags = exifread.process_file(img_file)
                for tag in tags:
                    metadata[tag] = str(tags[tag])

        elif ext == '.pdf':
            with open(file_path, 'rb') as pdf_file:
                pdf = PyPDF2.PdfReader(pdf_file)
                info = pdf.metadata
                for key, value in info.items():
                    metadata[key] = str(value)

        elif ext == '.docx':
            doc = docx.Document(file_path)
            props = doc.core_properties
            metadata = {
                'author': props.author,
                'title': props.title,
                'created': str(props.created),
                'last_modified_by': props.last_modified_by,
                'modified': str(props.modified),
            }

        else:
            metadata['Error'] = 'File type not supported for metadata.'

    except Exception as e:
        metadata['Error'] = f'Failed to extract metadata: {e}'

    return metadata

def calculate_hashes(file_path):
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256(),
    }
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for h in hashes.values():
                    h.update(chunk)
        return {k: v.hexdigest() for k, v in hashes.items()}
    except Exception as e:
        return {"Error": f"Gagal menghitung hash: {e}"}

def get_file_type(file_path):
    if magic:
        try:
            return magic.from_file(file_path)
        except Exception as e:
            return f"Error: {e}"
    else:
        return "Modul python-magic tidak ditemukan"

def get_file_basic_info(file_path):
    try:
        stat = os.stat(file_path)
        return {
            "File Name": os.path.basename(file_path),
            "Size (KB)": round(stat.st_size / 1024, 2),
            "Created": time.ctime(stat.st_ctime),
            "Modified": time.ctime(stat.st_mtime),
            "Accessed": time.ctime(stat.st_atime),
        }
    except Exception as e:
        return {"Error": f"Gagal membaca info dasar: {e}"}

def gps_to_maps(tags):
    try:
        lat_tag = tags.get('GPS GPSLatitude')
        lon_tag = tags.get('GPS GPSLongitude')
        lat_ref = tags.get('GPS GPSLatitudeRef').printable
        lon_ref = tags.get('GPS GPSLongitudeRef').printable

        if lat_tag and lon_tag:
            lat = convert_to_degrees(lat_tag)
            lon = convert_to_degrees(lon_tag)

            if lat_ref != "N":
                lat = -lat
            if lon_ref != "E":
                lon = -lon

            return f"https://www.google.com/maps?q={lat},{lon}"
    except:
        pass
    return None

def convert_to_degrees(value):
    d, m, s = [float(x.num) / float(x.den) for x in value.values]
    return d + (m / 60.0) + (s / 3600.0)

def open_file():
    file_path = filedialog.askopenfilename(
        title="Pilih file",
        filetypes=[("Supported Files", "*.pdf *.docx *.jpg *.jpeg")]
    )

    if not file_path:
        return

    file_label.config(text=f"📄 {os.path.basename(file_path)}")

    # Clear semua treeview
    for tree in [basic_tree, meta_tree, hash_tree, type_tree, gps_tree]:
        tree.delete(*tree.get_children())

    # Info dasar
    basic_info = get_file_basic_info(file_path)
    for k, v in basic_info.items():
        basic_tree.insert('', 'end', values=(k, v))

    # Metadata
    metadata = extract_metadata(file_path)
    for k, v in metadata.items():
        meta_tree.insert('', 'end', values=(k, v))

    # Hashes
    hashes = calculate_hashes(file_path)
    for k, v in hashes.items():
        hash_tree.insert('', 'end', values=(k, v))

    # File type
    file_type = get_file_type(file_path)
    type_tree.insert('', 'end', values=("Detected Type", file_type))

    # GPS (jika ada)
    if os.path.splitext(file_path)[-1].lower() in ['.jpg', '.jpeg']:
        with open(file_path, 'rb') as img_file:
            tags = exifread.process_file(img_file)
            gps_link = gps_to_maps(tags)
            if gps_link:
                gps_tree.insert('', 'end', values=("Google Maps", gps_link))
            else:
                gps_tree.insert('', 'end', values=("GPS", "Tidak ditemukan"))

# GUI START
app = ThemedTk(theme="arc")
app.title("🔍 Forensic Metadata Dashboard")
app.geometry("850x700")
app.resizable(False, False)

title = tk.Label(app, text="🕵️ Digital Forensics Tool", font=("Segoe UI", 18, "bold"))
title.pack(pady=10)

file_label = tk.Label(app, text="Belum ada file dipilih", font=("Segoe UI", 11))
file_label.pack(pady=2)

btn = ttk.Button(app, text="Pilih File", command=open_file)
btn.pack(pady=5)

tabControl = ttk.Notebook(app)
tabControl.pack(expand=1, fill="both", padx=10, pady=10)

# Tab-tab
tabs = {
    "Info Dasar": None,
    "Metadata": None,
    "Hash": None,
    "File Type": None,
    "Lokasi GPS": None,
}
trees = {}

for name in tabs:
    frame = ttk.Frame(tabControl)
    tabControl.add(frame, text=name)
    tree = ttk.Treeview(frame, columns=("Atribut", "Nilai"), show="headings", height=15)
    tree.heading("Atribut", text="Atribut")
    tree.heading("Nilai", text="Nilai")
    tree.column("Atribut", width=300)
    tree.column("Nilai", width=500)
    tree.pack(expand=True, fill='both', padx=10, pady=10)
    trees[name] = tree

basic_tree = trees["Info Dasar"]
meta_tree = trees["Metadata"]
hash_tree = trees["Hash"]
type_tree = trees["File Type"]
gps_tree = trees["Lokasi GPS"]

footer = tk.Label(app, text="by Nugra • Python Forensic Tool", font=("Segoe UI", 9), fg="gray")
footer.pack(pady=3)

app.mainloop()
