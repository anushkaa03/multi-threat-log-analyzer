import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os

class LogAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Log Analyzer - Multi Threat Detector")
        self.root.geometry("900x650")
        
        self.log_file_path = tk.StringVar()
        self.threshold = tk.IntVar(value=5)  # Failed attempts per minute
        self.start_hour = 9
        self.end_hour = 18
        
        self.setup_ui()
    
    def setup_ui(self):
        # File selection
        file_frame = tk.Frame(self.root)
        file_frame.pack(pady=10)
        tk.Label(file_frame, text="Log File Path:").pack(side=tk.LEFT)
        self.path_entry = tk.Entry(file_frame, textvariable=self.log_file_path, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        self.path_entry.config(state="readonly")
        
        # Threshold input
        thresh_frame = tk.Frame(self.root)
        thresh_frame.pack(pady=10)
        tk.Label(thresh_frame, text="Failed Attempts Threshold (per minute):").pack(side=tk.LEFT)
        tk.Entry(thresh_frame, textvariable=self.threshold, width=10).pack(side=tk.LEFT, padx=5)
        
        # Analyze button
        tk.Button(self.root, text="Analyze Logs", command=self.analyze_logs, bg="lightblue", font=("Arial", 12)).pack(pady=20)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(self.root, width=100, height=30, wrap=tk.WORD)
        self.results_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        if filename:
            self.log_file_path.set(filename)
            self.path_entry.config(state="normal")
            self.path_entry.config(state="readonly")
    
    def parse_log_line(self, line):
        """
        Parse log lines. Supports:
        Failed login, successful login with username, timestamps, IPs.
        Example formats:
        2025-09-25 01:00:01 192.168.0.10 Failed login
        2025-09-25 01:01:01 192.168.0.10 User admin login successful
        """
        fail_pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([\d.]+)\s+.*?(401|Failed login|Unauthorized|Login failed|Access denied)',
            re.IGNORECASE
        )
        success_pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([\d.]+)\s+User (\S+) login successful',
            re.IGNORECASE
        )
        match_fail = fail_pattern.search(line.strip())
        match_success = success_pattern.search(line.strip())
        
        if match_fail:
            timestamp_str = match_fail.group(1)
            ip = match_fail.group(2)
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                return ('fail', timestamp, ip, None)
            except ValueError:
                pass
        elif match_success:
            timestamp_str = match_success.group(1)
            ip = match_success.group(2)
            user = match_success.group(3)
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                return ('success', timestamp, ip, user)
            except ValueError:
                pass
        return None
    
    def analyze_logs(self):
        log_path = self.log_file_path.get().strip()
        if not log_path:
            messagebox.showerror("Error", "Please select a log file.")
            return
        if not os.path.isfile(log_path):
            messagebox.showerror("Error", "Invalid file path selected.")
            return
        
        threshold = self.threshold.get()
        if threshold <= 0:
            messagebox.showerror("Error", "Threshold must be positive.")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Analyzing log file: {log_path}\nThreshold: {threshold} failed attempts per minute\n\n")
        self.root.update()
        
        failed_attempts = defaultdict(list)  # IP → [timestamps]
        username_failures = defaultdict(lambda: defaultdict(list))  # username → IP → [timestamps]
        last_fail_per_user_ip = defaultdict(lambda: defaultdict(deque))  # user → IP → failed timestamps
        
        alerts = []
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue
                    type_, ts, ip, user = parsed
                    
                    # --- Brute force detection ---
                    if type_ == 'fail':
                        failed_attempts[ip].append(ts)
                        if user:
                            username_failures[user][ip].append(ts)
                    
                    # --- Suspicious login times ---
                    if type_ == 'success':
                        if ts.hour < self.start_hour or ts.hour >= self.end_hour:
                            alert_msg = f"ALERT: Suspicious login time by user '{user}' from IP {ip} at {ts}\n"
                            alerts.append(alert_msg)
                            self.results_text.insert(tk.END, alert_msg)
                        
                        # --- Repeated Success After Failures ---
                        fail_window = last_fail_per_user_ip[user][ip]
                        # Remove timestamps older than 1 hour
                        while fail_window and (ts - fail_window[0]) > timedelta(hours=1):
                            fail_window.popleft()
                        if len(fail_window) >= 3:  # threshold for multiple failed attempts
                            alert_msg = f"ALERT: Successful login after multiple failures by '{user}' from IP {ip} at {ts}\n"
                            alerts.append(alert_msg)
                            self.results_text.insert(tk.END, alert_msg)
                        # Clear failures after success
                        last_fail_per_user_ip[user][ip].clear()
                    
                    if type_ == 'fail' and user:
                        last_fail_per_user_ip[user][ip].append(ts)
            
            # --- Brute force detection per IP ---
            for ip, timestamps in failed_attempts.items():
                timestamps.sort()
                window = deque()
                for ts in timestamps:
                    window.append(ts)
                    while (ts - window[0]) > timedelta(minutes=1):
                        window.popleft()
                    if len(window) > threshold:
                        alert_msg = f"ALERT: Brute force detected from IP {ip} - {len(window)} failed attempts in 1 minute (window: {window[0]} to {window[-1]})\n"
                        alerts.append(alert_msg)
                        self.results_text.insert(tk.END, alert_msg)
            
            # --- Credential Stuffing detection ---
            for user, ip_dict in username_failures.items():
                all_fail_times = []
                for ip, times in ip_dict.items():
                    for ts in times:
                        all_fail_times.append((ts, ip))
                all_fail_times.sort()
                
                window = deque()
                for ts, ip in all_fail_times:
                    window.append((ts, ip))
                    while (ts - window[0][0]) > timedelta(minutes=1):
                        window.popleft()
                    unique_ips = set(ip for _, ip in window)
                    if len(unique_ips) > 2:  # 3+ IPs failing for same user
                        alert_msg = f"ALERT: Credential stuffing suspected for user '{user}' from IPs {unique_ips} within 1 minute\n"
                        alerts.append(alert_msg)
                        self.results_text.insert(tk.END, alert_msg)
            
            # --- Summary ---
            total_failed = sum(len(v) for v in failed_attempts.values())
            self.results_text.insert(tk.END, f"\n--- SUMMARY ---\n")
            self.results_text.insert(tk.END, f"Total failed login attempts: {total_failed}\n")
            self.results_text.insert(tk.END, f"Unique IPs with failures: {len(failed_attempts)}\n")
            self.results_text.insert(tk.END, f"Number of alerts detected: {len(alerts)}\n")
            if len(alerts) == 0:
                self.results_text.insert(tk.END, "No suspicious activity detected.\n")
            
            # --- Popup ---
            if len(alerts) > 0:
                messagebox.showwarning("Security Alerts", f"Detected {len(alerts)} suspicious events!")
            else:
                messagebox.showinfo("Analysis Complete", "Log analysis complete. No alerts triggered.")
        
        except Exception as e:
            msg = f"Error analyzing log: {e}"
            self.results_text.insert(tk.END, msg)
            messagebox.showerror("Error", msg)

def main():
    root = tk.Tk()
    
    app = LogAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
