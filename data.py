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
import mimetypes
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import json
from datetime import datetime
import csv

try:
    import magic
except ImportError:
    magic = None

class ForensicAnalyzer:
    def __init__(self):
        self.app = ThemedTk(theme="equilux")  # Modern dark theme
        self.app.title("🕵️‍♂️ Forensic File Analyzer Pro")
        self.app.geometry("1200x800")
        self.app.resizable(True, True)
        self.setup_ui()
        self.current_file = None
        self.comparison_file = None

    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.app)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="🔍 Forensic File Analyzer Pro", font=("Helvetica", 20, "bold")).pack(pady=10)
        
        # File selection section
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill="x", pady=5)
        self.file_label = ttk.Label(file_frame, text="No file selected", font=("Helvetica", 12))
        self.file_label.pack(side="left", padx=5)
        ttk.Button(file_frame, text="Select File", command=self.open_file).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Select Comparison File", command=self.open_comparison_file).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Export Report", command=self.export_report).pack(side="right", padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill="x", pady=5)

        # Tabs
        self.tabControl = ttk.Notebook(main_frame)
        self.tabControl.pack(expand=1, fill="both", pady=10)

        tabs = ["Basic Info", "Metadata", "Hash", "File Type", "Timeline", "Comparison"]
        self.trees = {}
        for name in tabs:
            frame = ttk.Frame(self.tabControl)
            self.tabControl.add(frame, text=name)
            if name != "Timeline":
                tree = ttk.Treeview(frame, columns=("Attribute", "Value"), show="headings", height=20)
                tree.heading("Attribute", text="Attribute")
                tree.heading("Value", text="Value")
                tree.column("Attribute", width=400)
                tree.column("Value", width=700)
                tree.pack(expand=True, fill='both', padx=10, pady=10)
                self.trees[name] = tree
            else:
                # Timeline visualization
                fig, ax = plt.subplots(figsize=(10, 4))
                canvas = FigureCanvasTkAgg(fig, master=frame)
                canvas.get_tk_widget().pack(expand=True, fill='both', padx=10, pady=10)
                self.trees[name] = (fig, ax, canvas)

        # Footer
        ttk.Label(main_frame, text="by Nugra • Python Forensic Inspector Pro", font=("Helvetica", 10), foreground="gray").pack(pady=5)

    def extract_metadata(self, file_path):
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
                metadata['Info'] = 'No specific metadata available for this file.'
        except Exception as e:
            metadata['Error'] = f'Failed to extract metadata: {e}'
        return metadata

    def calculate_hashes(self, file_path):
        hashes = {
            'MD5': hashlib.md5(),
            'SHA1': hashlib.sha1(),
            'SHA256': hashlib.sha256(),
            'SHA512': hashlib.sha512(),  # Added SHA512
        }
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)
            return {k: v.hexdigest() for k, v in hashes.items()}
        except Exception as e:
            return {"Error": f"Failed to calculate hash: {e}"}

    def get_file_type(self, file_path):
        if magic:
            try:
                return magic.from_file(file_path)
            except Exception as e:
                return f"Error: {e}"
        else:
            mime, _ = mimetypes.guess_type(file_path)
            return mime or "Unknown"

    def get_file_basic_info(self, file_path):
        try:
            stat = os.stat(file_path)
            return {
                "File Name": os.path.basename(file_path),
                "Full Path": os.path.abspath(file_path),
                "Size (KB)": round(stat.st_size / 1024, 2),
                "Size (MB)": round(stat.st_size / (1024 * 1024), 2),
                "Created": time.ctime(stat.st_ctime),
                "Modified": time.ctime(stat.st_mtime),
                "Accessed": time.ctime(stat.st_atime),
                "OS": platform.system(),
                "Platform": platform.platform(),
                "File Extension": os.path.splitext(file_path)[-1].lower(),
            }
        except Exception as e:
            return {"Error": f"Failed to read basic info: {e}"}

    def plot_timeline(self, file_path, ax):
        try:
            stat = os.stat(file_path)
            times = [
                ("Created", stat.st_ctime),
                ("Modified", stat.st_mtime),
                ("Accessed", stat.st_atime)
            ]
            labels, timestamps = zip(*times)
            dates = [datetime.fromtimestamp(ts) for ts in timestamps]
            
            ax.clear()
            ax.barh(labels, [1] * len(labels), left=dates, height=0.3)
            ax.set_title("File Timeline")
            ax.set_xlabel("Date")
            ax.grid(True, axis='x')
            self.trees["Timeline"][2].draw()
        except Exception as e:
            ax.clear()
            ax.text(0.5, 0.5, f"Error: {e}", ha='center', va='center')
            self.trees["Timeline"][2].draw()

    def compare_files(self):
        if not self.current_file or not self.comparison_file:
            messagebox.showwarning("Warning", "Please select both files to compare")
            return
        
        comparison = {
            "File 1": os.path.basename(self.current_file),
            "File 2": os.path.basename(self.comparison_file),
            "Same Size": os.path.getsize(self.current_file) == os.path.getsize(self.comparison_file),
            "Same Hash (SHA256)": self.calculate_hashes(self.current_file).get("SHA256") == 
                                 self.calculate_hashes(self.comparison_file).get("SHA256"),
            "Same Extension": os.path.splitext(self.current_file)[-1].lower() == 
                            os.path.splitext(self.comparison_file)[-1].lower()
        }
        
        self.trees["Comparison"].delete(*self.trees["Comparison"].get_children())
        for k, v in comparison.items():
            self.trees["Comparison"].insert('', 'end', values=(k, v))

    def export_report(self):
        if not self.current_file:
            messagebox.showwarning("Warning", "No file selected to export")
            return

        report = {
            "Basic Info": self.get_file_basic_info(self.current_file),
            "Metadata": self.extract_metadata(self.current_file),
            "Hashes": self.calculate_hashes(self.current_file),
            "File Type": {"Type": self.get_file_type(self.current_file)},
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
        )
        if file_path:
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(report, f, indent=4)
            elif file_path.endswith('.csv'):
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Category", "Attribute", "Value"])
                    for category, data in report.items():
                        for k, v in data.items():
                            writer.writerow([category, k, v])
            messagebox.showinfo("Success", "Report exported successfully!")

    def process_file(self, file_path, is_comparison=False):
        if not file_path:
            return

        if not is_comparison:
            self.current_file = file_path
            self.file_label.config(text=f"📄 {os.path.basename(file_path)}")
        else:
            self.comparison_file = file_path
            self.file_label.config(text=f"📄 Main: {os.path.basename(self.current_file)} | Compare: {os.path.basename(file_path)}")

        self.progress.start()
        for tree in [self.trees["Basic Info"], self.trees["Metadata"], self.trees["Hash"], self.trees["File Type"]]:
            tree.delete(*tree.get_children())

        basic_info = self.get_file_basic_info(file_path)
        for k, v in basic_info.items():
            self.trees["Basic Info"].insert('', 'end', values=(k, v))

        metadata = self.extract_metadata(file_path)
        for k, v in metadata.items():
            self.trees["Metadata"].insert('', 'end', values=(k, v))

        hashes = self.calculate_hashes(file_path)
        for k, v in hashes.items():
            self.trees["Hash"].insert('', 'end', values=(k, v))

        file_type = self.get_file_type(file_path)
        self.trees["File Type"].insert('', 'end', values=("File Type", file_type))

        if not is_comparison:
            self.plot_timeline(file_path, self.trees["Timeline"][1])
        
        if self.current_file and self.comparison_file:
            self.compare_files()

        self.progress.stop()

    def open_file(self):
        file_path = filedialog.askopenfilename(title="Select file", filetypes=[("All Files", "*.*")])
        if file_path:
            threading.Thread(target=self.process_file, args=(file_path,), daemon=True).start()

    def open_comparison_file(self):
        file_path = filedialog.askopenfilename(title="Select comparison file", filetypes=[("All Files", "*.*")])
        if file_path:
            threading.Thread(target=self.process_file, args=(file_path, True), daemon=True).start()

    def run(self):
        self.app.mainloop()

if __name__ == "__main__":
    analyzer = ForensicAnalyzer()
    analyzer.run()