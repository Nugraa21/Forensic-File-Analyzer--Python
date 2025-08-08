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
import stat
import math
import queue

try:
    import magic
except ImportError:
    magic = None

class ForensicAnalyzer:
    def __init__(self):
        self.app = ThemedTk(theme="equilux")
        self.app.title("Forensic File Analyzer Pro")
        self.app.geometry("1600x1000")
        self.app.resizable(True, True)
        self.app.minsize(1200, 700)
        self.current_file = None
        self.comparison_file = None
        self.task_queue = queue.Queue()
        self.setup_ui()
        self.process_queue()

    def setup_ui(self):
        # Custom style configuration
        style = ttk.Style()
        style.theme_use("equilux")
        style.configure("TButton", font=("Segoe UI", 14, "bold"), padding=15, background="#4CAF50", foreground="white", borderwidth=0)
        style.configure("TLabel", font=("Segoe UI", 12), foreground="white")
        style.configure("Treeview", font=("Segoe UI", 11), rowheight=32, background="#1e1e1e", fieldbackground="#1e1e1e", foreground="white")
        style.configure("Treeview.Heading", font=("Segoe UI", 12, "bold"), background="#0d0d0d", foreground="#4CAF50")
        style.map("TButton", background=[('active', '#45a049'), ('disabled', '#555555')], relief=[('active', 'flat')])
        style.configure("TNotebook", background="#0d0d0d", tabmargins=5)
        style.configure("TNotebook.Tab", font=("Segoe UI", 14), padding=[15, 8], background="#1e1e1e")
        style.map("TNotebook.Tab", background=[('selected', '#4CAF50'), ('active', '#BB86FC')])
        style.configure("Header.TFrame", background="#0d0d0d")

        # Main container
        self.main_container = ttk.Frame(self.app)
        self.main_container.pack(fill="both", expand=True)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(2, weight=1)

        # Header
        header_frame = ttk.Frame(self.main_container, style="Header.TFrame")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(10, 10))
        header_frame.configure(relief="flat", borderwidth=0)
        ttk.Label(header_frame, text="Forensic File Analyzer Pro", font=("Segoe UI", 36, "bold"), foreground="#4CAF50", background="#0d0d0d").pack(pady=(10, 5))
        ttk.Label(header_frame, text="Analyze Digital Evidence with Precision", font=("Segoe UI", 16, "italic"), foreground="#BB86FC", background="#0d0d0d").pack(pady=(0, 10))

        # Toolbar
        toolbar = ttk.Frame(self.main_container, style="Header.TFrame")
        toolbar.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        toolbar.grid_columnconfigure((0, 1, 2, 3), weight=1)
        buttons = [
            ("Select File", self.open_file, "Select a file for analysis"),
            ("Compare File", self.open_comparison_file, "Select a file to compare"),
            ("Export Report", self.export_report, "Export analysis as JSON/CSV"),
            ("Clear", self.clear_analysis, "Reset all analysis data")
        ]
        for i, (text, cmd, tooltip) in enumerate(buttons):
            btn = ttk.Button(toolbar, text=text, command=cmd, style="TButton")
            btn.grid(row=0, column=i, padx=10, pady=5, sticky="ew")
            self.add_tooltip(btn, tooltip)
            btn.bind("<Enter>", lambda e, b=btn: b.configure(style="TButton"))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(style="TButton"))

        # File label
        self.file_label = ttk.Label(self.main_container, text="No file selected", font=("Segoe UI", 14), foreground="#BB86FC")
        self.file_label.grid(row=2, column=0, sticky="w", padx=20, pady=5)

        # Progress bar
        style.configure("Horizontal.TProgressbar", troughcolor="#0d0d0d", background="#4CAF50")
        self.progress = ttk.Progressbar(self.main_container, mode='indeterminate', length=500)
        self.progress.grid(row=3, column=0, sticky="ew", padx=20, pady=10)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.main_container, textvariable=self.status_var, font=("Segoe UI", 10), relief="sunken", background="#0d0d0d", foreground="white")
        status_bar.grid(row=4, column=0, sticky="ew", padx=20, pady=5)

        # Tabs
        self.tabControl = ttk.Notebook(self.main_container)
        self.tabControl.grid(row=5, column=0, sticky="nsew", padx=20, pady=10)
        
        tabs = ["Dashboard", "Basic Info", "Metadata", "Hash", "File Type", "Timeline", "Comparison", "Advanced"]
        self.trees = {}
        for name in tabs:
            frame = ttk.Frame(self.tabControl)
            self.tabControl.add(frame, text=name)
            if name != "Timeline":
                tree = ttk.Treeview(frame, columns=("Attribute", "Value"), show="headings", height=25)
                tree.heading("Attribute", text="Attribute")
                tree.heading("Value", text="Value")
                tree.column("Attribute", width=600, anchor="w")
                tree.column("Value", width=1000, anchor="w")
                tree.pack(expand=True, fill='both', padx=20, pady=20)
                self.trees[name] = tree
                self.add_context_menu(tree)
            else:
                fig, ax = plt.subplots(figsize=(14, 6), facecolor='#0d0d0d')
                ax.set_facecolor('#0d0d0d')
                canvas = FigureCanvasTkAgg(fig, master=frame)
                canvas.get_tk_widget().pack(expand=True, fill='both', padx=20, pady=20)
                self.trees[name] = (fig, ax, canvas)

        # Footer
        ttk.Label(self.main_container, text="by Nugra • Python Forensic Inspector Pro", font=("Segoe UI", 10), foreground="#666666").grid(row=6, column=0, pady=10)

        # Bind tab switching animation
        self.tabControl.bind("<<NotebookTabChanged>>", self.animate_tab_switch)

    def add_tooltip(self, widget, text):
        def enter(event):
            x, y = widget.winfo_rootx() + 25, widget.winfo_rooty() + 25
            self.tooltip = tk.Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            label = ttk.Label(self.tooltip, text=text, background="#333333", foreground="white", relief="solid", borderwidth=1, padding=5)
            label.pack()
        def leave(event):
            if hasattr(self, 'tooltip'):
                self.tooltip.destroy()
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def add_context_menu(self, tree):
        menu = tk.Menu(self.app, tearoff=0)
        menu.add_command(label="Copy Value", command=lambda: self.copy_tree_value(tree))
        tree.bind("<Button-3>", lambda event: self.show_context_menu(event, menu))

    def show_context_menu(self, event, menu):
        try:
            menu.post(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_tree_value(self, tree):
        try:
            selected_item = tree.selection()[0]
            value = tree.item(selected_item, 'values')[1]
            self.app.clipboard_clear()
            self.app.clipboard_append(value)
            self.status_var.set("Value copied to clipboard")
        except:
            self.status_var.set("No value selected")

    def animate_tab_switch(self, event):
        self.app.after(50, lambda: self.tabControl.update())

    def calculate_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                return "Empty file"
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            entropy = 0
            for count in byte_counts:
                if count:
                    p = count / len(data)
                    entropy -= p * math.log2(p)
            return f"{entropy:.2f} bits/byte"
        except Exception as e:
            return f"Error: {e}"

    def check_file_signature(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8).hex().upper()
            signatures = {
                'FFD8FF': 'JPEG Image',
                '25504446': 'PDF Document',
                '504B0304': 'DOCX/Office Open XML',
                '7F454C46': 'ELF Executable',
            }
            for sig, desc in signatures.items():
                if header.startswith(sig):
                    return desc
            return "Unknown or no recognizable signature"
        except Exception as e:
            return f"Error: {e}"

    def extract_metadata(self, file_path):
        self.status_var.set("Extracting metadata...")
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
                    info = pdf.metadata or {}
                    for key, value in info.items():
                        metadata[key] = str(value)
            elif ext == '.docx':
                doc = docx.Document(file_path)
                props = doc.core_properties
                metadata = {
                    'Author': props.author or "Unknown",
                    'Title': props.title or "Untitled",
                    'Created': str(props.created) if props.created else "N/A",
                    'Last Modified By': props.last_modified_by or "Unknown",
                    'Modified': str(props.modified) if props.modified else "N/A",
                }
            else:
                metadata['Info'] = 'No specific metadata available.'
        except Exception as e:
            metadata['Error'] = f'Failed to extract metadata: {e}'
        self.status_var.set("Ready")
        return metadata

    def calculate_hashes(self, file_path):
        self.status_var.set("Calculating hashes...")
        hashes = {
            'MD5': hashlib.md5(),
            'SHA1': hashlib.sha1(),
            'SHA256': hashlib.sha256(),
            'SHA512': hashlib.sha512(),
        }
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)
            self.status_var.set("Ready")
            return {k: v.hexdigest() for k, v in hashes.items()}
        except Exception as e:
            self.status_var.set("Ready")
            return {"Error": f"Failed to calculate hash: {e}"}

    def get_file_type(self, file_path):
        self.status_var.set("Detecting file type...")
        if magic:
            try:
                result = magic.from_file(file_path)
                self.status_var.set("Ready")
                return result
            except Exception as e:
                self.status_var.set("Ready")
                return f"Error: {e}"
        else:
            mime, _ = mimetypes.guess_type(file_path)
            self.status_var.set("Ready")
            return mime or "Unknown"

    def get_file_basic_info(self, file_path):
        self.status_var.set("Retrieving basic info...")
        try:
            stat_info = os.stat(file_path)
            permissions = stat.filemode(stat_info.st_mode)
            return {
                "File Name": os.path.basename(file_path),
                "Full Path": os.path.abspath(file_path),
                "Size (KB)": f"{round(stat_info.st_size / 1024, 2)} KB",
                "Size (MB)": f"{round(stat_info.st_size / (1024 * 1024), 2)} MB",
                "Created": time.ctime(stat_info.st_ctime),
                "Modified": time.ctime(stat_info.st_mtime),
                "Accessed": time.ctime(stat_info.st_atime),
                "Permissions": permissions,
                "OS": platform.system(),
                "Platform": platform.platform(),
                "File Extension": os.path.splitext(file_path)[-1].lower(),
                "File Entropy": self.calculate_entropy(file_path),
                "File Signature": self.check_file_signature(file_path),
            }
        except Exception as e:
            self.status_var.set("Ready")
            return {"Error": f"Failed to read basic info: {e}"}

    def plot_timeline(self, file_path, ax):
        self.status_var.set("Generating timeline...")
        try:
            stat = os.stat(file_path)
            times = [
                ("Created", stat.st_ctime, '#4CAF50'),
                ("Modified", stat.st_mtime, '#2196F3'),
                ("Accessed", stat.st_atime, '#BB86FC')
            ]
            labels, timestamps, colors = zip(*times)
            dates = [datetime.fromtimestamp(ts) for ts in timestamps]
            
            ax.clear()
            ax.set_facecolor('#0d0d0d')
            bars = ax.barh(labels, [1] * len(labels), left=dates, height=0.3, color=colors, edgecolor='white', linewidth=1.5, alpha=0.9)
            ax.set_title("File Event Timeline", color='white', fontsize=16, pad=15)
            ax.set_xlabel("Date", color='white', fontsize=12)
            ax.tick_params(axis='both', colors='white', labelsize=10)
            ax.grid(True, axis='x', linestyle='--', alpha=0.7)
            
            # Add annotations with glowing effect
            for bar, date in zip(bars, dates):
                ax.text(date, bar.get_y() + bar.get_height()/2, date.strftime("%Y-%m-%d %H:%M:%S"),
                        va='center', ha='right', color='white', fontsize=10, bbox=dict(facecolor=bar.get_facecolor(), alpha=0.7, boxstyle="round,pad=0.3", edgecolor='white'))
            
            self.trees["Timeline"][2].draw()
            self.status_var.set("Ready")
        except Exception as e:
            ax.clear()
            ax.text(0.5, 0.5, f"Error: {e}", ha='center', va='center', color='white', fontsize=12)
            self.trees["Timeline"][2].draw()
            self.status_var.set("Ready")

    def update_dashboard(self):
        self.trees["Dashboard"].delete(*self.trees["Dashboard"].get_children())
        if not self.current_file:
            self.trees["Dashboard"].insert('', 'end', values=("Status", "No file selected"))
            return
        basic_info = self.get_file_basic_info(self.current_file)
        hashes = self.calculate_hashes(self.current_file)
        dashboard_data = {
            "File Name": basic_info.get("File Name", "N/A"),
            "Size": basic_info.get("Size (MB)", "N/A"),
            "SHA256": hashes.get("SHA256", "N/A")[:16] + "..." if hashes.get("SHA256") else "N/A",
            "File Type": self.get_file_type(self.current_file),
            "Last Modified": basic_info.get("Modified", "N/A"),
            "File Signature": basic_info.get("File Signature", "N/A"),
        }
        for k, v in dashboard_data.items():
            self.trees["Dashboard"].insert('', 'end', values=(k, v))

    def compare_files(self):
        if not self.current_file or not self.comparison_file:
            messagebox.showwarning("Warning", "Please select both files to compare")
            return
        
        self.status_var.set("Comparing files...")
        comparison = {
            "File 1": os.path.basename(self.current_file),
            "File 2": os.path.basename(self.comparison_file),
            "Same Size": os.path.getsize(self.current_file) == os.path.getsize(self.comparison_file),
            "Same Hash (SHA256)": self.calculate_hashes(self.current_file).get("SHA256") == 
                                 self.calculate_hashes(self.comparison_file).get("SHA256"),
            "Same Extension": os.path.splitext(self.current_file)[-1].lower() == 
                            os.path.splitext(self.comparison_file)[-1].lower(),
            "Size Difference (Bytes)": abs(os.path.getsize(self.current_file) - os.path.getsize(self.comparison_file)),
            "Signature Match": self.check_file_signature(self.current_file) == self.check_file_signature(self.comparison_file),
        }
        
        self.trees["Comparison"].delete(*self.trees["Comparison"].get_children())
        for k, v in comparison.items():
            self.trees["Comparison"].insert('', 'end', values=(k, v))
        self.status_var.set("Ready")

    def export_report(self):
        if not self.current_file:
            messagebox.showwarning("Warning", "No file selected to export")
            return

        self.status_var.set("Generating report...")
        report = {
            "Basic Info": self.get_file_basic_info(self.current_file),
            "Metadata": self.extract_metadata(self.current_file),
            "Hashes": self.calculate_hashes(self.current_file),
            "File Type": {"Type": self.get_file_type(self.current_file)},
            "Advanced": {
                "File Entropy": self.calculate_entropy(self.current_file),
                "File Signature": self.check_file_signature(self.current_file),
                "Permissions": self.get_file_basic_info(self.current_file).get("Permissions", "N/A"),
            },
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
        )
        if file_path:
            try:
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
                self.status_var.set("Ready")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")
                self.status_var.set("Ready")

    def clear_analysis(self):
        self.current_file = None
        self.comparison_file = None
        self.file_label.config(text="No file selected")
        for tree in self.trees.values():
            if isinstance(tree, tuple):
                tree[1].clear()
                tree[1].text(0.5, 0.5, "No data available", ha='center', va='center', color='white')
                tree[2].draw()
            else:
                tree.delete(*tree.get_children())
        self.status_var.set("Analysis cleared")

    def process_file(self, file_path, is_comparison=False):
        if not file_path:
            return

        self.status_var.set(f"Processing {os.path.basename(file_path)}...")
        if not is_comparison:
            self.current_file = file_path
            self.file_label.config(text=f"Main: {os.path.basename(file_path)}")
        else:
            self.comparison_file = file_path
            self.file_label.config(text=f"Main: {os.path.basename(self.current_file)} | Compare: {os.path.basename(file_path)}")

        self.progress.start()
        for tree in [self.trees["Basic Info"], self.trees["Metadata"], self.trees["Hash"], self.trees["File Type"], self.trees["Advanced"]]:
            tree.delete(*tree.get_children())

        # Basic Info
        basic_info = self.get_file_basic_info(file_path)
        for k, v in basic_info.items():
            self.trees["Basic Info"].insert('', 'end', values=(k, v))

        # Metadata
        metadata = self.extract_metadata(file_path)
        for k, v in metadata.items():
            self.trees["Metadata"].insert('', 'end', values=(k, v))

        # Hashes
        hashes = self.calculate_hashes(file_path)
        for k, v in hashes.items():
            self.trees["Hash"].insert('', 'end', values=(k, v))

        # File Type
        file_type = self.get_file_type(file_path)
        self.trees["File Type"].insert('', 'end', values=("File Type", file_type))

        # Advanced Info
        advanced_info = {
            "File Entropy": self.calculate_entropy(file_path),
            "File Signature": self.check_file_signature(file_path),
            "Permissions": basic_info.get("Permissions", "N/A"),
            "File Owner UID": str(os.stat(file_path).st_uid) if os.path.exists(file_path) else "N/A",
            "File Group GID": str(os.stat(file_path).st_gid) if os.path.exists(file_path) else "N/A",
        }
        for k, v in advanced_info.items():
            self.trees["Advanced"].insert('', 'end', values=(k, v))

        # Timeline
        if not is_comparison:
            self.plot_timeline(file_path, self.trees["Timeline"][1])

        # Dashboard
        self.update_dashboard()

        # Comparison
        if self.current_file and self.comparison_file:
            self.compare_files()

        self.progress.stop()
        self.status_var.set("Ready")

    def process_queue(self):
        try:
            file_path, is_comparison = self.task_queue.get_nowait()
            self.process_file(file_path, is_comparison)
        except queue.Empty:
            pass
        self.app.after(100, self.process_queue)

    def open_file(self):
        file_path = filedialog.askopenfilename(title="Select File for Analysis", filetypes=[("All Files", "*.*")])
        if file_path:
            self.task_queue.put((file_path, False))

    def open_comparison_file(self):
        file_path = filedialog.askopenfilename(title="Select Comparison File", filetypes=[("All Files", "*.*")])
        if file_path:
            self.task_queue.put((file_path, True))

    def run(self):
        self.app.mainloop()

if __name__ == "__main__":
    analyzer = ForensicAnalyzer()
    analyzer.run()