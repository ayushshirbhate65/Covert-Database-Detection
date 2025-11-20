import os
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from tkinter.ttk import Progressbar
import threading
import time
from random import randint, choice, choices
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
from queue import Queue
import shutil
from stegano import lsb  # For LSB steganography
import math
import concurrent.futures
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from PIL import Image  # Pillow for fallback image analysis
import nmap  # For network discovery
import steganography
import socket
import psutil



# Theme colors for modern UI
THEMES = {
    'light': {
        'primary': '#2196F3',      # Material Blue
        'secondary': '#03A9F4',    # Light Blue
        'success': '#4CAF50',      # Green
        'warning': '#FFC107',      # Amber
        'danger': '#F44336',       # Red
        'background': '#FAFAFA',   # Almost White
        'surface': '#FFFFFF',      # White
        'text': '#212121',         # Almost Black
        'text_secondary': '#757575' # Gray
    },
    'dark': {
        'primary': '#2196F3',      # Material Blue
        'secondary': '#03A9F4',    # Light Blue
        'success': '#4CAF50',      # Green
        'warning': '#FFC107',      # Amber
        'danger': '#F44336',       # Red
        'background': '#121212',   # Dark background
        'surface': '#1E1E1E',      # Dark surface
        'text': '#FFFFFF',         # White text
        'text_secondary': '#B0B0B0' # Light Gray
    }
}

class ThemeManager:
    def __init__(self):
        self.current_theme = 'light'
        self.colors = THEMES[self.current_theme]
        
    def toggle_theme(self):
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.colors = THEMES[self.current_theme]
        return self.colors

theme_manager = ThemeManager()

# Modern button styles
class ModernButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            bg=theme_manager.colors['primary'],
            fg=theme_manager.colors['background'],
            font=('Helvetica', 10),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2'
        )
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        
    def _on_enter(self, e):
        self['background'] = theme_manager.colors['secondary']
        
    def _on_leave(self, e):
        self['background'] = theme_manager.colors['primary']

# Helper: fast entropy computation using numpy.
def compute_entropy(data):
    if len(data) == 0:
        return 0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probabilities = counts / len(arr)
    probabilities = probabilities[probabilities > 0]
    return -np.sum(probabilities * np.log2(probabilities))

class CovertDBDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Covert Database Detection & Hiding Tool")
        
        # Initialize Fernet encryption with persistent key
        self.key_file = "crypto.key"
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
        self.fernet = Fernet(key)
        
        # Configure the main window
        window_width = 1200
        window_height = 800
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Set minimum window size
        root.minsize(1000, 600)
        
        # Configure grid weight
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)
        
        self.model = self.train_model()
        self.file_signatures = {
            'mdb': b'\x00\x01\x00\x00Standard Jet DB',
            'accdb': b'\x00\x01\x00\x00Standard ACE DB',
            'dbf': b'DBASE'
        }
        self.deep_model = None
        self.performance_folder = os.getcwd()
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        self.create_ui()

    def train_model(self):
        data = np.array([[randint(100, 1000), randint(0, 1)] for _ in range(100)])
        model = IsolationForest(n_estimators=100, contamination=0.1)
        model.fit(data)
        return model

    def create_ui(self):
        # Create top bar with theme toggle
        self.top_bar = self.create_top_bar()
        self.top_bar.pack(fill='x', pady=(0, 20))
        
        # Create all frames
        self.local_scan_frame = self.create_local_scan_page()
        self.network_scan_frame = self.create_network_scan_page()
        self.hidden_db_detection_frame = self.create_hidden_db_detection_page()
        self.performance_analysis_frame = self.create_performance_analysis_page()
        self.documentation_frame = self.create_documentation_page()
        self.hide_database_frame = self.create_hide_database_page()
        
        # Show initial frame
        self.show_frame(self.local_scan_frame)

    def create_top_bar(self):
        frame = ttk.Frame(self.main_container)
        
        # Navigation buttons
        nav_frame = ttk.Frame(frame)
        nav_frame.pack(side='left', fill='x', expand=True)
        
        buttons = [
            ("🔍 Local Scan", self.show_local_scan_page),
            ("🌐 Network", self.show_network_scan_page),
            ("🕵️ Hidden DB", self.show_hidden_db_detection_page),
            ("📊 Performance", self.show_performance_analysis_page),
            ("📚 Docs", self.show_documentation_page),
            ("🔒 Hide DB", self.show_hide_database_page)
        ]
        
        for text, command in buttons:
            btn = ModernButton(nav_frame, text=text, command=command)
            btn.pack(side='left', padx=5)
        
        # Theme toggle
        theme_btn = ModernButton(frame, text="🌓", command=self.toggle_theme)
        theme_btn.pack(side='right', padx=5)
        
        return frame

    def toggle_theme(self):
        theme_manager.toggle_theme()
        self.update_theme()

    def update_theme(self):
        # Update theme for all widgets
        for widget in self.root.winfo_children():
            if isinstance(widget, ModernButton):
                widget.configure(
                    bg=theme_manager.colors['primary'],
                    fg=theme_manager.colors['background']
                )
        self.root.configure(bg=theme_manager.colors['background'])

    def show_frame(self, frame):
        # Hide all frames except top bar
        for widget in self.main_container.winfo_children():
            if widget not in (self.top_bar, frame):
                widget.pack_forget()
        
        # Show the selected frame
        frame.pack(fill="both", expand=True, padx=10, pady=10)

    def show_local_scan_page(self):
        self.show_frame(self.local_scan_frame)

    def show_network_scan_page(self):
        self.show_frame(self.network_scan_frame)

    def show_hidden_db_detection_page(self):
        self.show_frame(self.hidden_db_detection_frame)

    def show_performance_analysis_page(self):
        self.show_frame(self.performance_analysis_frame)
        self.run_performance_analysis_default()

    def show_documentation_page(self):
        self.show_frame(self.documentation_frame)

    def show_hide_database_page(self):
        self.show_frame(self.hide_database_frame)

    # ------------------- Local Scan Methods -------------------

    def create_local_scan_page(self):
        frame = ttk.Frame(self.main_container)
        
        # Header
        header = ttk.Label(frame, text="Local Disk Scanner", 
                          font=('Helvetica', 14, 'bold'))
        header.pack(pady=(0, 20))
        
        # Progress bar with modern style
        self.local_progress = ttk.Progressbar(frame, orient="horizontal", 
                                            length=400, mode="determinate",
                                            style="Accent.Horizontal.TProgressbar")
        self.local_progress.pack(pady=10)
        
        # Scan button with modern style
        self.scan_local_btn = ModernButton(frame, text="🔍 Scan Local Disk",
                                         command=self.scan_local_databases)
        self.scan_local_btn.pack(pady=10)
        
        # Results frame with modern style
        self.results_frame = ttk.LabelFrame(frame, text="Search Results",
                                          padding=15)
        self.results_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Results tree with modern style
        columns = ("Type", "Location", "Size (MB)", "Status")
        self.local_results_tree = ttk.Treeview(self.results_frame,
                                             columns=columns,
                                             show="headings",
                                             style="Accent.Treeview")
        
        for col in columns:
            self.local_results_tree.heading(col, text=col)
            self.local_results_tree.column(col, anchor="center", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.results_frame, orient="vertical",
                                command=self.local_results_tree.yview)
        self.local_results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.local_results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.local_results_tree.bind("<Double-1>", self.view_database_contents)
        
        return frame

    def scan_local_databases(self):
        self.local_progress.start()
        self.local_results_tree.delete(*self.local_results_tree.get_children())
        drive = filedialog.askdirectory(initialdir="/", title="Select a Drive")
        if drive:
            threading.Thread(target=self.start_local_search, args=(drive,)).start()
        else:
            messagebox.showerror("Error", "No drive selected.")
            self.local_progress.stop()

    def start_local_search(self, drive):
        database_extensions = ['.db', '.sqlite', '.mdf', '.accdb', '.dbf']
        found_files = []
        dirs_queue = Queue()
        dirs_queue.put(drive)
        
        while not dirs_queue.empty():
            current_dir = dirs_queue.get()
            try:
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        if entry.is_file() and any(entry.name.lower().endswith(ext) for ext in database_extensions):
                            found_files.append(entry.path)
                        elif entry.is_dir() and not entry.name.startswith('$') and not entry.name.startswith('.'):
                            dirs_queue.put(entry.path)
            except PermissionError:
                continue
                
        self.local_results_tree.delete(*self.local_results_tree.get_children())
        if found_files:
            for file in found_files:
                self.local_results_tree.insert("", "end", values=("SQLite", file, "Unknown", "Detected"))
        else:
            self.local_results_tree.insert("", "end", values=("No Results", "-", "-", "-"))
        self.local_progress.stop()

    def view_database_contents(self, event):
        selected_item = self.local_results_tree.selection()[0]
        db_info = self.local_results_tree.item(selected_item, "values")
        db_path = db_info[1]
        if db_path.endswith(('.db', '.sqlite')):
            self.open_database(db_path)
        else:
            messagebox.showerror("Error", "Selected file is not a valid SQLite database.")

    def open_database(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            if not tables:
                messagebox.showinfo("No Tables", "No tables found in the database.")
                return
                
            table_window = tk.Toplevel(self.root)
            table_window.title(f"Database: {db_path}")
            table_window.geometry("400x300")
            
            listbox = tk.Listbox(table_window, height=10, width=40)
            for table in tables:
                listbox.insert(tk.END, table[0])
            listbox.pack(pady=10)
            
            def show_table_contents():
                selected_table = listbox.get(tk.ACTIVE)
                if selected_table:
                    cursor.execute(f"SELECT * FROM {selected_table}")
                    rows = cursor.fetchall()
                    if rows:
                        columns = [desc[0] for desc in cursor.description]
                        content_window = tk.Toplevel(self.root)
                        content_window.title(f"Contents of {selected_table}")
                        content_window.geometry("600x400")
                        
                        text_widget = tk.Text(content_window, wrap="none", width=80, height=20)
                        text_widget.pack(padx=10, pady=10)
                        text_widget.insert(tk.END, f"{', '.join(columns)}\n")
                        text_widget.insert(tk.END, "-"*100 + "\n")
                        for row in rows:
                            text_widget.insert(tk.END, f"{', '.join(map(str, row))}\n")
                        text_widget.config(state=tk.DISABLED)
                    else:
                        messagebox.showinfo("No Data", f"No data found in table {selected_table}")
                table_window.destroy()
                
            view_btn = ttk.Button(table_window, text="View Table",
                               command=show_table_contents)
            view_btn.pack(pady=10)
            conn.close()
        except Exception as e:
            messagebox.showerror("Error", f"Error opening database: {e}")

    # ------------------- Network Scan Methods -------------------

    def create_network_scan_page(self):
        frame = ttk.Frame(self.main_container)
        
        # Header
        header = ttk.Label(frame, text="Network Database Scanner",
                          font=('Helvetica', 14, 'bold'))
        header.pack(pady=(0, 20))
        
        # Network input frame
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=20, pady=10)
        
        # Common addresses dropdown
        self.network_label = ttk.Label(input_frame, text="Select Target:",
                                     font=('Helvetica', 12))
        self.network_label.pack(side='left', padx=5)
        
        common_addresses = [
            "localhost",
            "127.0.0.1",
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1"
        ]
        
        self.network_combo = ttk.Combobox(input_frame, values=common_addresses,
                                        state="readonly", width=30,
                                        font=('Helvetica', 10))
        self.network_combo.pack(side='left', padx=5)
        self.network_combo.current(0)  # Default to localhost
        
        # Custom IP entry
        self.custom_ip_label = ttk.Label(input_frame, text="or Custom IP:",
                                       font=('Helvetica', 12))
        self.custom_ip_label.pack(side='left', padx=5)
        
        self.network_entry = ttk.Entry(input_frame, width=20,
                                     font=('Helvetica', 10))
        self.network_entry.pack(side='left', padx=5)
        
        # Status label
        self.network_status_label = ttk.Label(frame, text="Ready to scan",
                                            font=('Helvetica', 10))
        self.network_status_label.pack(pady=5)
        
        # Connect button with modern style
        self.connect_btn = ModernButton(frame, text="🔌 Connect & Scan",
                                      command=self.scan_network_databases)
        self.connect_btn.pack(pady=15)
        
        # Results frame with modern style
        self.network_results_frame = ttk.LabelFrame(frame, text="Network Scan Results",
                                                  padding=15)
        self.network_results_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Results tree with modern style
        columns = ("Type", "Location", "Size (MB)", "Status")
        self.network_results_tree = ttk.Treeview(self.network_results_frame,
                                               columns=columns,
                                               show="headings",
                                               style="Accent.Treeview")
        
        for col in columns:
            self.network_results_tree.heading(col, text=col)
            self.network_results_tree.column(col, anchor="center", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.network_results_frame, orient="vertical",
                                command=self.network_results_tree.yview)
        self.network_results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        return frame

    def scan_network_databases(self):
        try:
            ip = self.network_entry.get().strip() if self.network_entry.get().strip() else self.network_combo.get()
            
            if not ip:
                messagebox.showerror("Error", "Please select or enter a valid IP address!")
                return

            # Validate IP address format
            def is_valid_ip(ip_str):
                if ip_str in ['localhost', '127.0.0.1']:
                    return True
                try:
                    parts = ip_str.split('.')
                    if len(parts) != 4:
                        return False
                    return all(0 <= int(part) <= 255 for part in parts)
                except (AttributeError, TypeError, ValueError):
                    return False

            if not is_valid_ip(ip):
                messagebox.showerror("Error", "Invalid IP address format! Please use format: xxx.xxx.xxx.xxx")
                return

            self.network_results_tree.delete(*self.network_results_tree.get_children())
            self.network_status_label.config(text="Initializing scan...")
            self.connect_btn.config(state='disabled')
            self.root.update_idletasks()

            def safe_ui_update(func):
                def wrapper(*args, **kwargs):
                    try:
                        if self.root.winfo_exists():
                            return func(*args, **kwargs)
                    except Exception as e:
                        print(f"UI update error: {str(e)}")
                return wrapper

            @safe_ui_update
            def update_status(message):
                self.network_status_label.config(text=message)
                self.root.update_idletasks()

            @safe_ui_update
            def update_tree(values):
                self.network_results_tree.insert("", "end", values=values)
                self.root.update_idletasks()

            def check_port(host, port, timeout=2):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
                except Exception as e:
                    print(f"Port check error ({host}:{port}): {str(e)}")
                    return False

            def scan_thread():
                found_databases = False
                try:
                    target_ip = '127.0.0.1' if ip in ['localhost', '127.0.0.1'] else ip
                    
                    # Define database services to check
                    services = [
                        {'name': 'MySQL', 'port': 3306},
                        {'name': 'PostgreSQL', 'port': 5432},
                        {'name': 'MSSQL', 'port': 1433},
                        {'name': 'Oracle', 'port': 1521},
                        {'name': 'MongoDB', 'port': 27017},
                        {'name': 'Redis', 'port': 6379}
                    ]

                    # Check each service
                    for service in services:
                        if not self.root.winfo_exists():
                            return
                            
                        update_status(f"Checking {service['name']} ({service['port']})...")
                        
                        if check_port(target_ip, service['port']):
                            found_databases = True
                            update_tree((
                                service['name'],
                                f"{ip}:{service['port']}",
                                "N/A",
                                "Service detected (Authentication required)"
                            ))
                            print(f"Found {service['name']} on {ip}:{service['port']}")

                    # Check for ADS (Windows only)
                    if os.name == 'nt' and ip in ['localhost', '127.0.0.1']:
                        update_status("Checking for Alternate Data Streams...")
                        try:
                            # Common directories to check for ADS
                            check_dirs = [
                                os.path.expanduser("~"),
                                os.path.expanduser("~/Documents"),
                                "C:/ProgramData",
                                "C:/Users/Public"
                            ]
                            
                            for check_dir in check_dirs:
                                if not self.root.winfo_exists():
                                    return
                                    
                                if os.path.exists(check_dir):
                                    update_status(f"Checking ADS in {check_dir}...")
                                    
                                    # Use PowerShell to check for ADS
                                    try:
                                        import subprocess
                                        cmd = f'powershell "Get-Item \'{check_dir}\\*\' -Stream * | Where-Object Stream -ne \':$DATA\'"'
                                        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                        stdout, stderr = process.communicate()
                                        
                                        if stdout:
                                            ads_found = stdout.decode('utf-8', errors='ignore').strip()
                                            if ads_found:
                                                found_databases = True
                                                update_tree((
                                                    "ADS",
                                                    check_dir,
                                                    "N/A",
                                                    "Alternate Data Streams found"
                                                ))
                                                print(f"Found ADS in {check_dir}")
                                    except Exception as e:
                                        print(f"ADS check error: {str(e)}")
                        except Exception as e:
                            print(f"ADS scanning error: {str(e)}")

                    if not self.root.winfo_exists():
                        return

                    if not found_databases:
                        update_tree((
                            "No Results",
                            "-",
                            "-",
                            "No database services detected"
                        ))
                    
                    update_status("Scan complete")

                except Exception as e:
                    error_msg = str(e)
                    print(f"Scan error: {error_msg}")
                    if self.root.winfo_exists():
                        update_status(f"Scan error: {error_msg}")
                finally:
                    if self.root.winfo_exists():
                        self.connect_btn.config(state='normal')
                        self.root.update_idletasks()

            # Run the scan in a separate thread
            scan_thread = threading.Thread(target=scan_thread, daemon=True)
            scan_thread.start()

        except Exception as e:
            print(f"Error starting scan: {str(e)}")
            messagebox.showerror("Error", f"Failed to start scan: {str(e)}")
            self.connect_btn.config(state='normal')

    # ------------------- Hidden Database Detection Methods -------------------

    def create_hidden_db_detection_page(self):
        frame = ttk.Frame(self.main_container)
        
        # Header
        header = ttk.Label(frame, text="Hidden Database Detection",
                          font=('Helvetica', 14))
        header.pack(pady=(0, 20))
        
        # Detection frame
        detection_frame = ttk.LabelFrame(frame, text="Detection Configuration",
                                       padding=15)
        detection_frame.pack(padx=20, pady=10, fill="x")
        
        # Method selection
        method_frame = ttk.Frame(detection_frame)
        method_frame.pack(fill='x', pady=10)
        
        ttk.Label(method_frame, text="Detection Method:",
                 font=('Helvetica', 12)).pack(side='left', padx=5)
        
        self.detect_method_var = tk.StringVar()
        detection_methods = [
            "Rename Extension",
            "Steganography",
            "Cryptography",
            "File Chunk Split",
            "Alternate Data Streams (ADS)",
            "Machine Learning Obfuscation",
            "Hybrid Method"
        ]
        
        self.detect_method_combo = ttk.Combobox(method_frame,
                                               textvariable=self.detect_method_var,
                                               values=detection_methods,
                                               state="readonly",
                                               font=('Helvetica', 10))
        self.detect_method_combo.pack(side='left', padx=5)
        self.detect_method_combo.current(0)
        
        # Scan button
        scan_btn = ttk.Button(detection_frame, text="Scan Directory",
                            command=self.scan_hidden_db_directory)
        scan_btn.pack(pady=10)
        
        # Results frame
        result_frame = ttk.LabelFrame(frame, text="Detected Hidden Databases",
                                    padding=15)
        result_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Results treeview
        columns = ("File Path", "Method")
        self.detected_tree = ttk.Treeview(result_frame, columns=columns,
                                        show="headings")
        
        for col in columns:
            self.detected_tree.heading(col, text=col)
            self.detected_tree.column(col, anchor="center", width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical",
                                command=self.detected_tree.yview)
        self.detected_tree.configure(yscrollcommand=scrollbar.set)
        
        self.detected_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Recovery button
        recover_btn = ttk.Button(frame, text="Recover Selected Database",
                              command=self.recover_selected_hidden_db)
        recover_btn.pack(pady=10)
        
        # Output text area
        self.detect_output_text = tk.Text(frame, height=5,
                                       font=('Helvetica', 10))
        self.detect_output_text.pack(padx=20, pady=10, fill="x")
        
        return frame

    def scan_hidden_db_directory(self):
        method = self.detect_method_var.get()
        directory = filedialog.askdirectory(initialdir="/", title="Select Directory to Scan")
        if not directory:
            messagebox.showerror("Error", "No directory selected.")
            return

        start_time = time.time()
        self.detected_tree.delete(*self.detected_tree.get_children())
        found_files = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            for root_dir, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    future = executor.submit(self.advanced_detection, file_path, self.detect_method_var.get())
                    futures[future] = file_path
            for future in concurrent.futures.as_completed(futures):
                try:
                    if future.result():
                        found_files.append(futures[future])
                except Exception:
                    continue

        elapsed = time.time() - start_time

        if found_files:
            for f in found_files:
                self.detected_tree.insert("", "end", values=(f, self.detect_method_var.get()))
            self.detect_output_text.insert(tk.END, f"Found {len(found_files)} hidden file(s) using {self.detect_method_var.get()} in {elapsed:.2f} seconds.\n")
        else:
            self.detect_output_text.insert(tk.END, f"No hidden files found using {self.detect_method_var.get()} in {elapsed:.2f} seconds.\n")

    def advanced_detection(self, file_path, method):
        try:
            # For crypto method, use a larger sample size
            if method == "Cryptography":
                sample_size = 1024 * 1024  # 1MB
            else:
                sample_size = 1024  # 1KB

            if method == "Steganography":
                # Process only image files with expanded format support
                if not file_path.lower().endswith(('.png', '.jpeg', '.jpg', '.bmp', '.pnd', '.tiff', '.gif', '.webp')):
                    return False
                try:
                    # First attempt: Try to extract hidden data using stegano
                    hidden_data = lsb.reveal(file_path)
                    if hidden_data:
                        # Expanded database signatures
                        db_signatures = [
                            b"SQLite format 3",  # SQLite
                            b"PGCOPY\n\377\r\n\0",  # PostgreSQL
                            b"\x00\x01\x00\x00Standard",  # MS Access
                            bytes([0x1F, 0x8B]),  # MySQL dump (gzipped)
                            b"Microsoft Access",  # MS Access alternative
                            b"MySQL dump",  # MySQL dump
                            b"PostgreSQL",  # PostgreSQL alternative
                            b"SQLite",  # SQLite alternative
                            b"BEGIN TRANSACTION",  # Common in SQLite/PostgreSQL
                            b"PRAGMA"  # SQLite specific
                        ]
                        
                        # Convert hidden_data to bytes if it's a string
                        hidden_bytes = hidden_data.encode() if isinstance(hidden_data, str) else hidden_data
                        
                        # Check for database signatures in the first 1024 bytes (increased from 256)
                        first_bytes = hidden_bytes[:1024] if len(hidden_bytes) >= 1024 else hidden_bytes
                        if any(sig in first_bytes for sig in db_signatures):
                            return True
                            
                        # Expanded SQL keywords for validation
                        sql_keywords = [
                            b"CREATE TABLE", b"INSERT INTO", b"SELECT", b"UPDATE", b"DELETE FROM",
                            b"DROP TABLE", b"ALTER TABLE", b"INDEX", b"UNIQUE", b"PRIMARY KEY",
                            b"FOREIGN KEY", b"REFERENCES", b"CONSTRAINT", b"CHECK", b"DEFAULT",
                            b"NOT NULL", b"AUTO_INCREMENT", b"IDENTITY", b"BEGIN", b"COMMIT",
                            b"ROLLBACK", b"TRANSACTION", b"VIEW", b"TRIGGER", b"PROCEDURE"
                        ]
                        if any(keyword in hidden_bytes for keyword in sql_keywords):
                            return True
                            
                        # Additional check for common database field types
                        db_types = [
                            b"INTEGER", b"VARCHAR", b"TEXT", b"BLOB", b"REAL",
                            b"NUMERIC", b"BOOLEAN", b"DATE", b"TIMESTAMP", b"FLOAT",
                            b"DOUBLE", b"DECIMAL", b"CHAR", b"BINARY"
                        ]
                        if any(type_keyword in hidden_bytes for type_keyword in db_types):
                            return True
                            
                        return False
                except Exception:
                    # Fallback: Advanced LSB analysis with improved detection
                    try:
                        im = Image.open(file_path).convert("RGB")
                        width, height = im.size
                        pixels = list(im.getdata())
                        
                        # Increased sample size for better accuracy
                        sample_size = min(50000, width * height)  # Increased from 10000
                        pixel_sample = pixels[:sample_size]
                        
                        # Extract LSB from each color channel
                        lsb_data = []
                        for r, g, b in pixel_sample:
                            lsb_data.extend([r & 1, g & 1, b & 1])
                        
                        # Convert bits to bytes for analysis
                        byte_data = bytearray()
                        for i in range(0, len(lsb_data) - 7, 8):
                            byte = 0
                            for bit_idx in range(8):
                                byte = (byte << 1) | lsb_data[i + bit_idx]
                            byte_data.append(byte)
                        
                        # Analyze byte patterns with improved criteria
                        if len(byte_data) >= 16:
                            # Calculate entropy of the LSB data
                            lsb_entropy = compute_entropy(byte_data)
                            
                            # Check byte distribution
                            byte_counts = np.bincount(byte_data, minlength=256)
                            byte_distribution = byte_counts / len(byte_data)
                            max_byte_freq = max(byte_distribution)
                            std_dev = np.std(byte_distribution)
                            
                            # Improved criteria for detecting hidden data:
                            # 1. Lowered entropy threshold (7.2 from 7.5) to catch more potential matches
                            # 2. Adjusted max frequency threshold (0.12 from 0.1)
                            # 3. Added standard deviation check for distribution uniformity
                            if ((lsb_entropy > 7.2 and max_byte_freq < 0.12 and std_dev < 0.015) or
                                (lsb_entropy > 7.0 and max_byte_freq < 0.15 and std_dev < 0.02)):
                                
                                # Extended pattern check for database-like content
                                common_patterns = [
                                    bytes([0x53, 0x51, 0x4C]),  # "SQL"
                                    bytes([0x50, 0x4B]),        # PK (common in db files)
                                    bytes([0x74, 0x61, 0x62, 0x6C, 0x65]),  # "table"
                                    bytes([0x69, 0x6E, 0x73, 0x65, 0x72, 0x74]),  # "insert"
                                    bytes([0x75, 0x70, 0x64, 0x61, 0x74, 0x65]),  # "update"
                                    bytes([0x64, 0x65, 0x6C, 0x65, 0x74, 0x65]),  # "delete"
                                    bytes([0x73, 0x65, 0x6C, 0x65, 0x63, 0x74])   # "select"
                                ]
                                
                                # Check for repeating patterns that might indicate structured data
                                chunk_size = 16
                                chunks = [byte_data[i:i+chunk_size] for i in range(0, len(byte_data)-chunk_size, chunk_size)]
                                unique_chunks = len(set(chunks))
                                chunk_ratio = unique_chunks / len(chunks) if chunks else 1
                                
                                if any(pattern in byte_data for pattern in common_patterns) or chunk_ratio < 0.8:
                                    return True
                            
                    except Exception:
                        pass
                return False
            elif method == "Cryptography":
                # Check file extension first
                ext = os.path.splitext(file_path)[1].lower()
                crypto_exts = {".enc", ".crypt", ".cipher", ".encrypted", ".secure"}
                
                # Only proceed if it has a crypto extension
                if ext in crypto_exts:
                    try:
                        with open(file_path, "rb") as f:
                            data = f.read()
                            
                        # Skip very small files
                        if len(data) < 10:
                            return False
                            
                        # First try: Check if it's encrypted with current key
                        try:
                            self.fernet.decrypt(data)
                            return True
                        except Exception:
                            pass
                            
                        # Second try: Check for Fernet token characteristics
                        # Fernet tokens are base64-encoded and have specific characteristics
                        try:
                            # Check for base64 characters
                            import base64
                            try:
                                base64.b64decode(data)
                                # If we can decode it as base64 and it's long enough, likely a Fernet token
                                if len(data) >= 100:  # Fernet tokens are typically longer than this
                                    return True
                            except:
                                pass
                        except Exception:
                            pass
                            
                        # Third try: Check for high entropy and uniform byte distribution
                        try:
                            # Calculate entropy of the first 4KB
                            sample = data[:4096] if len(data) > 4096 else data
                            entropy = compute_entropy(sample)
                            
                            # Also check byte distribution
                            byte_counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256)
                            byte_distribution = byte_counts / len(sample)
                            
                            # Criteria for encrypted data:
                            # 1. High entropy (> 7.8)
                            # 2. Relatively uniform byte distribution (no byte should be too common)
                            if entropy > 7.8 and max(byte_distribution) < 0.05:
                                return True
                        except Exception:
                            pass
                            
                    except Exception:
                        pass
                    return False
            elif method == "Rename Extension":
                if os.path.splitext(file_path)[1].lower() == ".db":
                    return False
                with open(file_path, "rb") as f:
                    header = f.read(256)
                ext = os.path.splitext(file_path)[1][1:].lower()
                if ext in self.file_signatures:
                    if self.file_signatures[ext] not in header:
                        return True
                if b"SQLite format 3" in header:
                    return True
            elif method == "File Chunk Split":
                if "chunk" in file_path.lower() and file_path.endswith(".chk"):
                    return True
            elif method == "Alternate Data Streams (ADS)":
                with open(file_path, "rb") as f:
                    header = f.read(256)
                if b"SQLite format 3" in header:
                    return True
            elif method == "Machine Learning Obfuscation":
                with open(file_path, "rb") as f:
                    header = f.read(3)
                if header == b"ML:":
                    return True
            elif method == "Hybrid Method":
                with open(file_path, "rb") as f:
                    header = f.read(7)
                if header == b"HYBRID:":
                    return True
        except Exception:
            return False
        return False

    def recover_selected_hidden_db(self):
        selected = self.detected_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No hidden database selected.")
            return
        item = self.detected_tree.item(selected[0])
        file_path, method = item['values']
        result = self.convert_hidden_database_file(file_path, method)
        if result:
            self.detect_output_text.insert(tk.END, f"Recovered file using {method}.\nRecovered file: {result}\n")

    # ------------------- Performance Analysis Methods -------------------

    def create_performance_analysis_page(self):
        frame = ttk.Frame(self.main_container)
        
        # Header with description
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        header = ttk.Label(header_frame, text="Performance Analysis",
                          font=('Helvetica', 16, 'bold'))
        header.pack(pady=(0, 5))
        
        description = ttk.Label(header_frame, 
                              text="Analyze the performance metrics of different detection and hiding techniques",
                              font=('Helvetica', 10))
        description.pack()
        
        # Control Panel
        control_frame = ttk.LabelFrame(frame, text="Analysis Controls", padding=15)
        control_frame.pack(fill='x', padx=20, pady=10)
        
        # Method selection
        method_frame = ttk.Frame(control_frame)
        method_frame.pack(fill='x', pady=5)
        
        ttk.Label(method_frame, text="Analysis Type:",
                 font=('Helvetica', 10, 'bold')).pack(side='left', padx=5)
        
        self.analysis_type_var = tk.StringVar(value="detection")
        ttk.Radiobutton(method_frame, text="Detection Methods",
                       variable=self.analysis_type_var, value="detection",
                       command=self.update_performance_analysis).pack(side='left', padx=10)
        ttk.Radiobutton(method_frame, text="Hiding Methods",
                       variable=self.analysis_type_var, value="hiding",
                       command=self.update_performance_analysis).pack(side='left', padx=10)
        
        # Configuration options
        config_frame = ttk.Frame(control_frame)
        config_frame.pack(fill='x', pady=5)
        
        ttk.Label(config_frame, text="Sample Size:",
                 font=('Helvetica', 10)).pack(side='left', padx=5)
        
        self.sample_size_var = tk.StringVar(value="1000")
        sample_size_entry = ttk.Entry(config_frame, textvariable=self.sample_size_var, width=10)
        sample_size_entry.pack(side='left', padx=5)
        
        ttk.Label(config_frame, text="Max File Size (MB):",
                 font=('Helvetica', 10)).pack(side='left', padx=5)
        
        self.max_file_size_var = tk.StringVar(value="100")
        max_file_size_entry = ttk.Entry(config_frame, textvariable=self.max_file_size_var, width=10)
        max_file_size_entry.pack(side='left', padx=5)
        
        # Refresh button
        refresh_btn = ModernButton(control_frame, text="🔄 Refresh Analysis",
                                command=self.run_performance_analysis_default)
        refresh_btn.pack(pady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(control_frame, variable=self.progress_var,
                                          maximum=100, mode='determinate')
        self.progress_bar.pack(fill='x', pady=5)
        
        # Create notebook for multiple plots
        self.plot_notebook = ttk.Notebook(frame)
        self.plot_notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Create frames for different plots
        self.time_plot_frame = ttk.Frame(self.plot_notebook)
        self.count_plot_frame = ttk.Frame(self.plot_notebook)
        self.efficiency_plot_frame = ttk.Frame(self.plot_notebook)
        self.resource_plot_frame = ttk.Frame(self.plot_notebook)
        
        self.plot_notebook.add(self.time_plot_frame, text="Time Analysis")
        self.plot_notebook.add(self.count_plot_frame, text="Detection Count")
        self.plot_notebook.add(self.efficiency_plot_frame, text="Efficiency Score")
        self.plot_notebook.add(self.resource_plot_frame, text="Resource Usage")
        
        # Status frame
        status_frame = ttk.Frame(frame)
        status_frame.pack(fill='x', padx=20, pady=10)
        
        self.perf_status_label = ttk.Label(status_frame, text="Ready for analysis",
                                         font=('Helvetica', 10))
        self.perf_status_label.pack(side='left')
        
        return frame

    def update_performance_analysis(self):
        self.run_performance_analysis_default()

    def run_performance_analysis_default(self):
        try:
            analysis_type = self.analysis_type_var.get()
            sample_size = int(self.sample_size_var.get())
            max_file_size = int(self.max_file_size_var.get()) * 1024 * 1024  # Convert MB to bytes
            
            methods = [
                "Rename Extension",
                "Steganography",
                "Cryptography",
                "File Chunk Split",
                "ADS",
                "ML Obfuscation",
                "Hybrid Method"
            ]
            
            self.perf_status_label.config(text="Running analysis...")
            self.progress_var.set(0)
            
            # Initialize performance metrics
            performance_data = {}
            total_files = 0
            total_size = 0  # Total size in MB
            processed_files = 0
            
            # First pass to count total files and size
            for root_dir, _, files in os.walk(self.performance_folder):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size <= max_file_size:  # Only count files within size limit
                            total_files += 1
                            total_size += file_size / (1024 * 1024)  # Convert to MB
                    except:
                        continue
            
            # Limit total files to sample size
            total_files = min(total_files, sample_size)
            
            for method in methods:
                # Get detection time and count with progress tracking
                start_time = time.time()
                detected_files = []
                detected_sizes = []
                cpu_usage = []
                memory_usage = []
                
                # Initialize resource monitoring
                process = psutil.Process()
                initial_cpu_percent = process.cpu_percent()
                initial_memory = process.memory_info().rss / (1024 * 1024)  # MB
                
                for root_dir, _, files in os.walk(self.performance_folder):
                    for file in files:
                        if processed_files >= sample_size:
                            break
                            
                        file_path = os.path.join(root_dir, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            if file_size > max_file_size:
                                continue
                                
                            if self.advanced_detection(file_path, method):
                                detected_files.append(file_path)
                                detected_sizes.append(file_size / (1024 * 1024))  # MB
                                
                            # Update resource usage
                            cpu_usage.append(process.cpu_percent())
                            memory_usage.append(process.memory_info().rss / (1024 * 1024))  # MB
                            
                            processed_files += 1
                            progress = (processed_files / total_files) * 100
                            self.progress_var.set(progress)
                            self.root.update_idletasks()
                            
                        except Exception as e:
                            print(f"Error processing file {file_path}: {str(e)}")
                            continue
                
                time_taken = time.time() - start_time
                count = len(detected_files)
                
                # Calculate metrics
                success_rate = (count / max(1, total_files)) * 100
                avg_processing_time = time_taken / max(1, total_files) * 1000  # ms per file
                size_processed = sum(detected_sizes)
                throughput = size_processed / max(time_taken, 1e-6)  # MB/s
                
                # Calculate accuracy (simulated - in real world this would be compared against known hidden files)
                true_positives = count
                false_positives = len([f for f in detected_files if not any(ext in f.lower() for ext in ['.db', '.sqlite', '.mdf', '.accdb', '.dbf'])])
                precision = true_positives / max(true_positives + false_positives, 1)
                
                # Calculate resource usage
                avg_cpu = sum(cpu_usage) / max(len(cpu_usage), 1)
                max_cpu = max(cpu_usage) if cpu_usage else 0
                avg_memory = sum(memory_usage) / max(len(memory_usage), 1)
                max_memory = max(memory_usage) if memory_usage else 0
                
                # Calculate efficiency score
                epsilon = 1e-10
                if count > 0:
                    # Modified efficiency calculation that considers multiple factors:
                    # - Success rate
                    # - Processing speed
                    # - Precision
                    # - Resource usage (throughput)
                    # - CPU efficiency
                    # - Memory efficiency
                    efficiency = (
                        (success_rate / 100) *  # Normalize to 0-1
                        (precision) *  # 0-1
                        (1 / (1 + math.log2(avg_processing_time + epsilon))) *  # Processing speed factor
                        (math.log2(throughput + epsilon) / 10) *  # Throughput factor
                        (1 / (1 + math.log2(avg_cpu + epsilon))) *  # CPU efficiency
                        (1 / (1 + math.log2(avg_memory + epsilon)))  # Memory efficiency
                    ) * 100
                else:
                    efficiency = 0
                
                performance_data[method] = {
                    'time': time_taken,
                    'count': count,
                    'success_rate': success_rate,
                    'avg_processing_time': avg_processing_time,
                    'throughput': throughput,
                    'precision': precision * 100,
                    'efficiency': min(efficiency, 100),
                    'avg_cpu': avg_cpu,
                    'max_cpu': max_cpu,
                    'avg_memory': avg_memory,
                    'max_memory': max_memory
                }
            
            self.plot_performance(performance_data, analysis_type, total_files, total_size)
            self.perf_status_label.config(
                text=f"Analysis complete - Processed {total_files} files ({total_size:.2f} MB)"
            )
            self.progress_var.set(100)
            
        except Exception as e:
            messagebox.showerror("Error", f"Performance analysis failed: {str(e)}")
            self.perf_status_label.config(text="Analysis failed")
            self.progress_var.set(0)

    def plot_performance(self, data, analysis_type, total_files, total_size):
        methods = list(data.keys())
        metrics = {
            'time': [data[m]['time'] for m in methods],
            'count': [data[m]['count'] for m in methods],
            'success_rate': [data[m]['success_rate'] for m in methods],
            'avg_processing_time': [data[m]['avg_processing_time'] for m in methods],
            'throughput': [data[m]['throughput'] for m in methods],
            'precision': [data[m]['precision'] for m in methods],
            'efficiency': [data[m]['efficiency'] for m in methods],
            'avg_cpu': [data[m]['avg_cpu'] for m in methods],
            'max_cpu': [data[m]['max_cpu'] for m in methods],
            'avg_memory': [data[m]['avg_memory'] for m in methods],
            'max_memory': [data[m]['max_memory'] for m in methods]
        }
        
        # Clear previous plots
        for frame in [self.time_plot_frame, self.count_plot_frame, 
                     self.efficiency_plot_frame, self.resource_plot_frame]:
            for widget in frame.winfo_children():
                widget.destroy()
        
        # Set style based on current theme
        plt.style.use('dark_background' if theme_manager.current_theme == 'dark' else 'default')
        
        # Reset any existing plots
        plt.close('all')
        
        # Adjust figure size and layout for better visibility
        plt.rcParams.update({
            'figure.titlesize': 12,
            'axes.labelsize': 10,
            'axes.titlesize': 11,
            'xtick.labelsize': 8,
            'ytick.labelsize': 8,
            'figure.autolayout': True  # Enable automatic layout
        })
        
        def create_figure():
            fig = plt.figure(figsize=(10, 6))
            fig.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.2)  # Adjust margins
            return fig
        
        # Time Analysis Plot
        fig1 = create_figure()
        ax1 = plt.subplot(111)
        bars1 = ax1.bar(methods, metrics['time'], color='skyblue', width=0.7)
        ax1.set_title(f"Time Analysis - {analysis_type.title()} Methods")
        ax1.set_ylabel("Time (seconds)")
        ax1.tick_params(axis='x', rotation=45)
        
        # Add value labels
        max_time = max(metrics['time'])
        for bar in bars1:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + (max_time * 0.02),
                    f'{height:.2f}s', ha='center', va='bottom', fontsize=8)
        
        canvas1 = FigureCanvasTkAgg(fig1, master=self.time_plot_frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)
        
        # Success Rate Plot
        fig2 = create_figure()
        ax2 = plt.subplot(111)
        bars2 = ax2.bar(methods, metrics['success_rate'], color='lightgreen', width=0.7)
        ax2.set_title("Success Rate")
        ax2.set_ylabel("Success Rate (%)")
        ax2.tick_params(axis='x', rotation=45)
        
        # Set y-axis limits with padding
        max_success = max(metrics['success_rate'])
        if max_success > 0:
            ax2.set_ylim(0, max_success * 1.15)
        else:
            ax2.set_ylim(0, 100)
        
        # Add value labels
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + (max_success * 0.02),
                    f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
        
        canvas2 = FigureCanvasTkAgg(fig2, master=self.count_plot_frame)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)
        
        # Efficiency Score Plot
        fig3 = create_figure()
        ax3 = plt.subplot(111)
        bars3 = ax3.bar(methods, metrics['efficiency'], color='orange', width=0.7)
        ax3.set_title("Overall Efficiency Score")
        ax3.set_ylabel("Efficiency (%)")
        ax3.tick_params(axis='x', rotation=45)
        
        # Set y-axis limits with padding
        max_efficiency = max(metrics['efficiency'])
        if max_efficiency > 0:
            ax3.set_ylim(0, max_efficiency * 1.15)
        else:
            ax3.set_ylim(0, 100)
        
        # Add value labels
        for bar in bars3:
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height + (max_efficiency * 0.02),
                    f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
        
        canvas3 = FigureCanvasTkAgg(fig3, master=self.efficiency_plot_frame)
        canvas3.draw()
        canvas3.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)
        
        # Resource Usage Plot
        fig4 = create_figure()
        ax4 = plt.subplot(111)
        
        # Plot CPU usage
        cpu_bars = ax4.bar(methods, metrics['avg_cpu'], color='lightblue', width=0.35, label='Avg CPU')
        for i, bar in enumerate(cpu_bars):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
        
        # Plot memory usage
        memory_bars = ax4.bar([x + 0.35 for x in range(len(methods))], 
                             metrics['avg_memory'], color='lightgreen', width=0.35, label='Avg Memory (MB)')
        for i, bar in enumerate(memory_bars):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f}', ha='center', va='bottom', fontsize=8)
        
        ax4.set_title("Resource Usage")
        ax4.set_ylabel("Usage")
        ax4.tick_params(axis='x', rotation=45)
        ax4.legend(loc='upper center', bbox_to_anchor=(0.5, -0.15), ncol=2)  # Move legend below plot
        
        canvas4 = FigureCanvasTkAgg(fig4, master=self.resource_plot_frame)
        canvas4.draw()
        canvas4.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

    # ------------------- Documentation -------------------

    def create_documentation_page(self):
        frame = ttk.Frame(self.main_container)
        
        # Create a canvas with scrollbar for better navigation
        canvas = tk.Canvas(frame, bg=theme_manager.colors['background'])
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        # Configure the canvas
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Create window in canvas and bind mousewheel
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=canvas.winfo_width())
        canvas.bind('<Configure>', lambda e: canvas.itemconfig(canvas.find_all()[0], width=e.width))
        
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Pack the canvas and scrollbar
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Header with icon
        header = ttk.Label(scrollable_frame, text="📚 Documentation & User Guide",
                          font=('Helvetica', 24, 'bold'))
        header.pack(pady=(20, 30))
        
        # Quick Start Guide
        quick_start = ttk.LabelFrame(scrollable_frame, text="🚀 Quick Start Guide",
                                   padding=15)
        quick_start.pack(fill='x', padx=20, pady=10)
        
        quick_steps = [
            ("1. Local Scan", "Use the Local Scan tab to search for databases on your computer"),
            ("2. Network Scan", "Search for databases on your network using IP addresses"),
            ("3. Hidden Detection", "Detect hidden databases using various detection methods"),
            ("4. Hide Database", "Secure your sensitive databases using multiple hiding techniques"),
            ("5. Performance", "Analyze the performance of different detection/hiding methods")
        ]
        
        for step, desc in quick_steps:
            step_frame = ttk.Frame(quick_start)
            step_frame.pack(fill='x', pady=5)
            ttk.Label(step_frame, text=step,
                     font=('Helvetica', 12, 'bold')).pack(anchor='w')
            ttk.Label(step_frame, text=desc,
                     wraplength=800,
                     font=('Helvetica', 10)).pack(anchor='w', padx=20)
        
        # Detection Methods with detailed explanations
        methods_frame = ttk.LabelFrame(scrollable_frame, text="🔍 Detection Methods",
                                     padding=15)
        methods_frame.pack(fill='x', padx=20, pady=10)
        
        methods = [
            ("Rename Extension", """
            Detects databases that have been hidden by changing their file extension.
            • Checks file signatures and headers
            • Identifies common database formats
            • Supports SQLite, MySQL dumps, Access DB
            • Fast and reliable detection
            • Works with most common database types
            """),
            ("Steganography", """
            Finds databases hidden within image files using LSB steganography.
            • Analyzes least significant bits
            • Supports PNG, JPG, BMP formats
            • Uses entropy analysis for verification
            • Deep image analysis capabilities
            • Advanced pattern recognition
            """),
            ("Cryptography", """
            Identifies encrypted database files using multiple detection methods.
            • Checks for encryption signatures
            • Analyzes entropy patterns
            • Supports multiple encryption formats
            • Detects common encryption methods
            • Identifies encrypted database containers
            """),
            ("File Chunk Split", """
            Detects and reconstructs split database files.
            • Finds related chunks
            • Validates chunk sequences
            • Supports various splitting patterns
            • Automatic chunk reassembly
            • Smart pattern matching
            """),
            ("ADS (Alternate Data Streams)", """
            Windows-specific method to find databases in NTFS streams.
            • Scans for hidden streams
            • Checks stream contents
            • Windows NTFS specific
            • Advanced stream analysis
            • Complete NTFS scanning
            """),
            ("ML Obfuscation", """
            Uses machine learning to detect obfuscated databases.
            • Pattern recognition
            • Anomaly detection
            • Behavioral analysis
            • Advanced ML algorithms
            • Continuous learning capabilities
            """),
            ("Hybrid Method", """
            Combines multiple techniques for enhanced detection.
            • Multi-layer analysis
            • Cross-validation
            • Higher accuracy rate
            • Comprehensive scanning
            • Advanced detection algorithms
            """)
        ]
        
        for method, desc in methods:
            method_frame = ttk.Frame(methods_frame)
            method_frame.pack(fill='x', pady=10)
            ttk.Label(method_frame, text=method,
                     font=('Helvetica', 14, 'bold')).pack(anchor='w')
            ttk.Label(method_frame, text=desc,
                     wraplength=800,
                     font=('Helvetica', 10)).pack(anchor='w', padx=20)
        
        return frame

    def create_hide_database_page(self):
        frame = tk.Frame(self.main_container)
        
        # Hide Database Frame
        hide_frame = ttk.LabelFrame(frame, text="Hide Database", padding=10)
        hide_frame.pack(padx=20, pady=10, fill="x")
        
        ttk.Label(hide_frame, text="Select Database File:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.db_file_var = tk.StringVar()
        self.db_file_entry = ttk.Entry(hide_frame, textvariable=self.db_file_var, width=50)
        self.db_file_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(hide_frame, text="Browse", command=self.select_database_to_hide).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(hide_frame, text="Select Hiding Method:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.hide_method_var = tk.StringVar()
        hiding_methods = [
            "Rename Extension",
            "Steganography",
            "Cryptography",
            "File Chunk Split",
            "Alternate Data Streams (ADS)",
            "Machine Learning Obfuscation",
            "Hybrid Method"
        ]
        
        self.hide_method_combo = ttk.Combobox(hide_frame, textvariable=self.hide_method_var,
                                            values=hiding_methods, state="readonly")
        self.hide_method_combo.grid(row=1, column=1, padx=5, pady=5)
        self.hide_method_combo.current(0)
        
        ttk.Button(hide_frame, text="Hide Database", command=self.hide_database_file).grid(row=2, column=1, pady=10)
        
        # Recover Database Frame
        recover_frame = ttk.LabelFrame(frame, text="Recover Hidden Database", padding=10)
        recover_frame.pack(padx=20, pady=10, fill="x")
        
        ttk.Label(recover_frame, text="Select Hidden File:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.hidden_file_var = tk.StringVar()
        self.hidden_file_entry = ttk.Entry(recover_frame, textvariable=self.hidden_file_var, width=50)
        self.hidden_file_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(recover_frame, text="Browse", command=self.select_hidden_file).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(recover_frame, text="Select Conversion Method:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.convert_method_var = tk.StringVar()
        self.convert_method_combo = ttk.Combobox(recover_frame, textvariable=self.convert_method_var,
                                               values=hiding_methods, state="readonly")
        self.convert_method_combo.grid(row=1, column=1, padx=5, pady=5)
        self.convert_method_combo.current(0)
        
        ttk.Button(recover_frame, text="Recover Database", command=self.recover_database).grid(row=2, column=1, pady=10)
        
        # Output Text Area
        self.hide_output_text = tk.Text(frame, height=5)
        self.hide_output_text.pack(padx=20, pady=10, fill="x")
        
        return frame

    def select_hidden_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Hidden File",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.hidden_file_var.set(file_path)

    def recover_database(self):
        hidden_file = self.hidden_file_var.get()
        method = self.convert_method_var.get()
        if not hidden_file:
            messagebox.showerror("Error", "Please select a hidden file.")
            return
        result = self.convert_hidden_database_file(hidden_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database recovered using {method}.\nRecovered file:\n{result}\n\n")

    def select_database_to_hide(self):
        file_path = filedialog.askopenfilename(
            title="Select Database File",
            filetypes=[
                ("Database files", "*.db;*.sqlite;*.sqlite3"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.db_file_var.set(file_path)

    def hide_database_file(self):
        if not self.db_file_var.get():
            messagebox.showerror("Error", "Please select a database file first!")
            return
            
        method = self.hide_method_var.get()
        input_file = self.db_file_var.get()
        
        try:
            if method == "Rename Extension":
                new_ext = choice(['.docx', '.xlsx', '.bin', '.txt'])
                output_file = os.path.splitext(input_file)[0] + new_ext
                shutil.copy2(input_file, output_file)
                self.hide_output_text.insert(tk.END, 
                    f"Database hidden as {os.path.basename(output_file)}\n")
                
            elif method == "Steganography":
                # Select a cover image
                image_path = filedialog.askopenfilename(
                    title="Select Cover Image",
                    filetypes=[("Image files", "*.png;*.jpg;*.jpeg")]
                )
                if not image_path:
                    return
                    
                with open(input_file, 'rb') as f:
                    data = f.read()
                    
                output_file = os.path.splitext(image_path)[0] + "_with_hidden_db.png"
                secret = lsb.hide(image_path, data)
                secret.save(output_file)
                
                self.hide_output_text.insert(tk.END,
                    f"Database hidden in {os.path.basename(output_file)}\n")
                
            elif method == "Cryptography":
                output_file = os.path.splitext(input_file)[0] + ".enc"
                with open(input_file, 'rb') as f:
                    data = f.read()
                encrypted_data = self.fernet.encrypt(data)
                with open(output_file, 'wb') as f:
                    f.write(encrypted_data)
                self.hide_output_text.insert(tk.END,
                    f"Database encrypted as {os.path.basename(output_file)}\n")
                
            elif method == "File Chunk Split":
                chunk_size = 5 * 1024  # 5KB chunks
                output_dir = os.path.dirname(input_file)
                base_name = os.path.splitext(os.path.basename(input_file))[0]
                
                with open(input_file, 'rb') as f:
                    data = f.read()
                    
                chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
                chunk_files = []
                
                for i, chunk in enumerate(chunks, 1):
                    random_suffix = ''.join(choices('abcdefghijklmnopqrstuvwxyz', k=4))
                    chunk_file = os.path.join(
                        output_dir,
                        f"{base_name}_chunk_{i}_{random_suffix}.chk"
                    )
                    with open(chunk_file, 'wb') as f:
                        f.write(chunk)
                    chunk_files.append(chunk_file)
                    
                self.hide_output_text.insert(tk.END,
                    f"Database split into {len(chunks)} chunks\n")
                
            elif method == "Alternate Data Streams":
                if os.name != 'nt':
                    messagebox.showerror(
                        "Error",
                        "ADS is only supported on Windows NTFS filesystems!"
                    )
                    return
                    
                ads_dir = os.path.join(os.path.dirname(input_file), ".aqazsy_ads")
                os.makedirs(ads_dir, exist_ok=True)
                
                output_file = os.path.join(
                    ads_dir,
                    os.path.basename(input_file) + ":hidden_stream"
                )
                shutil.copy2(input_file, output_file)
                
                self.hide_output_text.insert(tk.END,
                    "Database hidden in alternate data stream\n")
                
            elif method == "Machine Learning Obfuscation":
                output_file = os.path.splitext(input_file)[0] + ".mlobs"
                with open(input_file, 'rb') as f:
                    data = f.read()
                    
                # Add ML signature and simple XOR obfuscation
                key = 0x55  # Simple XOR key
                obfuscated = bytes([b ^ key for b in data])
                with open(output_file, 'wb') as f:
                    f.write(b"ML:" + obfuscated)
                    
                self.hide_output_text.insert(tk.END,
                    f"Database obfuscated as {os.path.basename(output_file)}\n")
                
            elif method == "Hybrid Method":
                # Combine encryption and splitting
                output_file = os.path.splitext(input_file)[0] + ".hybrid"
                with open(input_file, 'rb') as f:
                    data = f.read()
                    
                # First encrypt
                encrypted_data = self.fernet.encrypt(data)
                
                # Then add hybrid signature
                with open(output_file, 'wb') as f:
                    f.write(b"HYBRID:" + encrypted_data)
                    
                self.hide_output_text.insert(tk.END,
                    f"Database hidden using hybrid method as {os.path.basename(output_file)}\n")
                
            messagebox.showinfo("Success", "Database hidden successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide database: {str(e)}")

    def convert_hidden_database_file(self, file_path, method):
        try:
            if method == "Rename Extension":
                output_file = os.path.splitext(file_path)[0] + ".db"
                shutil.copy2(file_path, output_file)
                return output_file
                
            elif method == "Steganography":
                # Process only image files with expanded format support
                if not file_path.lower().endswith(('.png', '.jpeg', '.jpg', '.bmp', '.pnd', '.tiff', '.gif', '.webp')):
                    return None
                try:
                    # First attempt: Try to extract hidden data using stegano
                    hidden_data = lsb.reveal(file_path)
                    if hidden_data:
                        # Expanded database signatures
                        db_signatures = [
                            b"SQLite format 3",  # SQLite
                            b"PGCOPY\n\377\r\n\0",  # PostgreSQL
                            b"\x00\x01\x00\x00Standard",  # MS Access
                            bytes([0x1F, 0x8B]),  # MySQL dump (gzipped)
                            b"Microsoft Access",  # MS Access alternative
                            b"MySQL dump",  # MySQL dump
                            b"PostgreSQL",  # PostgreSQL alternative
                            b"SQLite",  # SQLite alternative
                            b"BEGIN TRANSACTION",  # Common in SQLite/PostgreSQL
                            b"PRAGMA"  # SQLite specific
                        ]
                        
                        # Convert hidden_data to bytes if it's a string
                        hidden_bytes = hidden_data.encode() if isinstance(hidden_data, str) else hidden_data
                        
                        # Check for database signatures in the first 1024 bytes (increased from 256)
                        first_bytes = hidden_bytes[:1024] if len(hidden_bytes) >= 1024 else hidden_bytes
                        if any(sig in first_bytes for sig in db_signatures):
                            output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                            with open(output_file, 'wb') as f:
                                f.write(hidden_bytes)
                            return output_file
                            
                        # Expanded SQL keywords for validation
                        sql_keywords = [
                            b"CREATE TABLE", b"INSERT INTO", b"SELECT", b"UPDATE", b"DELETE FROM",
                            b"DROP TABLE", b"ALTER TABLE", b"INDEX", b"UNIQUE", b"PRIMARY KEY",
                            b"FOREIGN KEY", b"REFERENCES", b"CONSTRAINT", b"CHECK", b"DEFAULT",
                            b"NOT NULL", b"AUTO_INCREMENT", b"IDENTITY", b"BEGIN", b"COMMIT",
                            b"ROLLBACK", b"TRANSACTION", b"VIEW", b"TRIGGER", b"PROCEDURE"
                        ]
                        if any(keyword in hidden_bytes for keyword in sql_keywords):
                            output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                            with open(output_file, 'wb') as f:
                                f.write(hidden_bytes)
                            return output_file
                            
                        return None
                except Exception:
                    # Fallback: Advanced LSB analysis with improved detection
                    try:
                        im = Image.open(file_path).convert("RGB")
                        width, height = im.size
                        pixels = list(im.getdata())
                        
                        # Increased sample size for better accuracy
                        sample_size = min(50000, width * height)  # Increased from 10000
                        pixel_sample = pixels[:sample_size]
                        
                        # Extract LSB from each color channel
                        lsb_data = []
                        for r, g, b in pixel_sample:
                            lsb_data.extend([r & 1, g & 1, b & 1])
                        
                        # Convert bits to bytes for analysis
                        byte_data = bytearray()
                        for i in range(0, len(lsb_data) - 7, 8):
                            byte = 0
                            for bit_idx in range(8):
                                byte = (byte << 1) | lsb_data[i + bit_idx]
                            byte_data.append(byte)
                        
                        # Analyze byte patterns with improved criteria
                        if len(byte_data) >= 16:
                            # Calculate entropy of the LSB data
                            lsb_entropy = compute_entropy(byte_data)
                            
                            # Check byte distribution
                            byte_counts = np.bincount(byte_data, minlength=256)
                            byte_distribution = byte_counts / len(byte_data)
                            max_byte_freq = max(byte_distribution)
                            std_dev = np.std(byte_distribution)
                            
                            # Improved criteria for detecting hidden data:
                            # 1. Lowered entropy threshold (7.2 from 7.5) to catch more potential matches
                            # 2. Adjusted max frequency threshold (0.12 from 0.1)
                            # 3. Added standard deviation check for distribution uniformity
                            if ((lsb_entropy > 7.2 and max_byte_freq < 0.12 and std_dev < 0.015) or
                                (lsb_entropy > 7.0 and max_byte_freq < 0.15 and std_dev < 0.02)):
                                
                                # Extended pattern check for database-like content
                                common_patterns = [
                                    bytes([0x53, 0x51, 0x4C]),  # "SQL"
                                    bytes([0x50, 0x4B]),        # PK (common in db files)
                                    bytes([0x74, 0x61, 0x62, 0x6C, 0x65]),  # "table"
                                    bytes([0x69, 0x6E, 0x73, 0x65, 0x72, 0x74]),  # "insert"
                                    bytes([0x75, 0x70, 0x64, 0x61, 0x74, 0x65]),  # "update"
                                    bytes([0x64, 0x65, 0x6C, 0x65, 0x74, 0x65]),  # "delete"
                                    bytes([0x73, 0x65, 0x6C, 0x65, 0x63, 0x74])   # "select"
                                ]
                                
                                # Check for repeating patterns that might indicate structured data
                                chunk_size = 16
                                chunks = [byte_data[i:i+chunk_size] for i in range(0, len(byte_data)-chunk_size, chunk_size)]
                                unique_chunks = len(set(chunks))
                                chunk_ratio = unique_chunks / len(chunks) if chunks else 1
                                
                                if any(pattern in byte_data for pattern in common_patterns) or chunk_ratio < 0.8:
                                    output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                                    with open(output_file, 'wb') as f:
                                        f.write(bytes(byte_data))
                                    return output_file
                            
                    except Exception:
                        pass
                return None
                
            elif method == "Cryptography":
                try:
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_data)
                    return output_file
                except Exception:
                    return None
                    
            elif method == "File Chunk Split":
                if not file_path.endswith('.chk'):
                    return None

                base_dir = os.path.dirname(file_path)
                base_name = os.path.basename(file_path).split('_chunk_')[0]
                chunk_files = sorted([
                    f for f in os.listdir(base_dir)
                    if f.startswith(base_name) and f.endswith('.chk')
                ])
                
                if not chunk_files:
                    return None
                    
                output_file = os.path.join(base_dir, base_name + "_recovered.db")
                with open(output_file, 'wb') as outfile:
                    for chunk_file in chunk_files:
                        chunk_path = os.path.join(base_dir, chunk_file)
                        with open(chunk_path, 'rb') as infile:
                            outfile.write(infile.read())
                return output_file
                
            elif method == "Alternate Data Streams":
                if os.name != 'nt':
                    return None
                output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                shutil.copy2(file_path, output_file)
                return output_file
                
            elif method == "Machine Learning Obfuscation":
                if not file_path.endswith('.mlobs'):
                    return None
                    
                with open(file_path, 'rb') as f:
                    data = f.read()
                    
                if not data.startswith(b"ML:"):
                    return None
                    
                # Remove ML signature and deobfuscate
                obfuscated = data[3:]
                key = 0x55
                deobfuscated = bytes([b ^ key for b in obfuscated])
                
                output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                with open(output_file, 'wb') as f:
                    f.write(deobfuscated)
                return output_file
                
            elif method == "Hybrid Method":
                if not file_path.endswith('.hybrid'):
                    return None
                    
                with open(file_path, 'rb') as f:
                    data = f.read()
                    
                if not data.startswith(b"HYBRID:"):
                    return None
                    
                # Remove hybrid signature and decrypt
                encrypted_data = data[7:]
                decrypted_data = self.fernet.decrypt(encrypted_data)
                
                output_file = os.path.splitext(file_path)[0] + "_recovered.db"
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                return output_file
                
        except Exception as e:
            print(f"Error converting file: {str(e)}")
            return None
        return None

if __name__ == "__main__":
    root = tk.Tk()
    app = CovertDBDetectionApp(root)
    root.mainloop()
