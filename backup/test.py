import tkinter as tk
from tkinter import filedialog, ttk
from ttkthemes import ThemedTk
import os
import time
import hashlib
import exifread
import PyPDF2
import docx
import platform
import mimetypes

try:
    import magic  # Untuk deteksi file type
except ImportError:
    magic = None  # Kalau gak ada, fallback pakai mimetypes

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
                'Author': props.author,
                'Title': props.title,
                'Created': str(props.created),
                'Last Modified By': props.last_modified_by,
                'Modified': str(props.modified),
            }

        else:
            metadata['Info'] = 'Tidak ada metadata khusus untuk file ini.'

    except Exception as e:
        metadata['Error'] = f'Gagal mengambil metadata: {e}'

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
        mime, _ = mimetypes.guess_type(file_path)
        return mime or "Tidak diketahui"

def get_file_basic_info(file_path):
    try:
        stat = os.stat(file_path)
        return {
            "Nama File": os.path.basename(file_path),
            "Path Lengkap": os.path.abspath(file_path),
            "Ukuran (KB)": round(stat.st_size / 1024, 2),
            "Waktu Dibuat": time.ctime(stat.st_ctime),
            "Waktu Diubah": time.ctime(stat.st_mtime),
            "Waktu Diakses": time.ctime(stat.st_atime),
            "Sistem Operasi": platform.system(),
            "Platform": platform.platform(),
        }
    except Exception as e:
        return {"Error": f"Gagal membaca info dasar: {e}"}

def open_file():
    file_path = filedialog.askopenfilename(
        title="Pilih file",
        filetypes=[("Semua File", "*.*")]
    )

    if not file_path:
        return

    file_label.config(text=f"📄 {os.path.basename(file_path)}")

    # Kosongkan semua tabel
    for tree in [basic_tree, meta_tree, hash_tree, type_tree]:
        tree.delete(*tree.get_children())

    # Tampilkan info dasar
    basic_info = get_file_basic_info(file_path)
    for k, v in basic_info.items():
        basic_tree.insert('', 'end', values=(k, v))

    # Metadata
    metadata = extract_metadata(file_path)
    for k, v in metadata.items():
        meta_tree.insert('', 'end', values=(k, v))

    # Hash
    hashes = calculate_hashes(file_path)
    for k, v in hashes.items():
        hash_tree.insert('', 'end', values=(k, v))

    # Tipe file
    file_type = get_file_type(file_path)
    type_tree.insert('', 'end', values=("Jenis File", file_type))

# GUI Setup
app = ThemedTk(theme="arc")
app.title("🕵️ Forensic File Analyzer - Versi Lengkap")
app.geometry("900x700")
app.resizable(False, False)

# Title & Label
tk.Label(app, text="🔍 Forensic File Analyzer", font=("Segoe UI", 18, "bold")).pack(pady=10)
file_label = tk.Label(app, text="Belum ada file dipilih", font=("Segoe UI", 11))
file_label.pack(pady=2)
ttk.Button(app, text="Pilih File", command=open_file).pack(pady=5)

# Tabs
tabControl = ttk.Notebook(app)
tabControl.pack(expand=1, fill="both", padx=10, pady=10)

tabs = {
    "Info Dasar": None,
    "Metadata": None,
    "Hash": None,
    "Jenis File": None,
}
trees = {}

for name in tabs:
    frame = ttk.Frame(tabControl)
    tabControl.add(frame, text=name)
    tree = ttk.Treeview(frame, columns=("Atribut", "Nilai"), show="headings", height=15)
    tree.heading("Atribut", text="Atribut")
    tree.heading("Nilai", text="Nilai")
    tree.column("Atribut", width=300)
    tree.column("Nilai", width=550)
    tree.pack(expand=True, fill='both', padx=10, pady=10)
    trees[name] = tree

# Treeview Assignments
basic_tree = trees["Info Dasar"]
meta_tree = trees["Metadata"]
hash_tree = trees["Hash"]
type_tree = trees["Jenis File"]

# Footer
tk.Label(app, text="by Nugra • Python Forensic Inspector", font=("Segoe UI", 9), fg="gray").pack(pady=5)
app.mainloop()
