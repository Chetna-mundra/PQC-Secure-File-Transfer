import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
from network.client import send_file


BG_MAIN = "#1e1e2e"      
TEXT_COLOR = "#ffffff"   
SUB = "#89b4fa"   
LOG_BG = "#11111b"        
LOG_FG = "#50fa7b"       

def select_file():
    chosen_file = filedialog.askopenfilename()
    if chosen_file:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, chosen_file)


def run_network(path, host, port):
    try:
        log_box.insert(tk.END, f"connecting to {host}:{port}...\n")
        log_box.insert(tk.END, "ML-KEM-768 key encapsulation...\n")
        log_box.see(tk.END)

        result = send_file(file_path=path, host=host, port=port)

        log_box.insert(tk.END, "shared secret established via ML-KEM.\n")
        log_box.insert(tk.END, "file encrypted with AES-256-GCM and sent.\n")
        log_box.insert(tk.END, f"server verified SHA-256: {result['sha256']}\n")
        log_box.insert(tk.END, "SUCCESS: Transfer complete!\n\n")
        log_box.see(tk.END)

        status_label.config(text="Status: Transfer Successful!", fg="#50fa7b")
        messagebox.showinfo("Success", "File sent and verified successfully!")
    except Exception as e:
        log_box.insert(tk.END, f"[ERROR] {e}\n\n")
        log_box.see(tk.END)
        status_label.config(text="Status: Transfer Failed!", fg="#f38ba8")
        messagebox.showerror("Error", str(e))
    finally:
        send_btn.config(state=tk.NORMAL)

def start_transfer():
    path = file_entry.get().strip()
    host = host_entry.get().strip()

    if not path:
        messagebox.showwarning("Warning", "Please select a file first!")
        return

    try:
        port = int(port_entry.get().strip())
    except ValueError:
        messagebox.showerror("Error", "Port must be a number!")
        return

    send_btn.config(state=tk.DISABLED)
    status_label.config(text="Status: Sending...", fg="#89b4fa")
    log_box.delete(1.0, tk.END)

    #threading so tht GUI doesn't freeze during network socket operations
    thread = threading.Thread(target=run_network, args=(path, host, port), daemon=True)
    thread.start()

#gui
window = tk.Tk()
window.title("PQC Secure File Transfer - Client")
window.geometry("640x520")
window.configure(bg=BG_MAIN)

#title
title_label = tk.Label(
    window, 
    text="Post-Quantum Secure File Transfer", 
    font=("Arial", 15, "bold"),
    bg=BG_MAIN,
    fg=TEXT_COLOR
)
title_label.pack(pady=(15, 2))

subtitle_label = tk.Label(
    window, 
    text="NIST FIPS 203 (ML-KEM-768)  •  AES-256-GCM  •  SHA-256", 
    font=("Arial", 10), 
    bg=BG_MAIN, 
    fg=SUB
)
subtitle_label.pack(pady=(0, 10))

#host and port
config_frame = tk.Frame(window, bg=BG_MAIN)
config_frame.pack(pady=4)

tk.Label(config_frame, text="Host:", font=("Arial", 10, "bold"), bg=BG_MAIN, fg=TEXT_COLOR).pack(side=tk.LEFT, padx=3)
host_entry = tk.Entry(config_frame, width=16, font=("Arial", 10))
host_entry.insert(0, "127.0.0.1")
host_entry.pack(side=tk.LEFT, padx=(2, 16))

tk.Label(config_frame, text="Port:", font=("Arial", 10, "bold"), bg=BG_MAIN, fg=TEXT_COLOR).pack(side=tk.LEFT, padx=3)
port_entry = tk.Entry(config_frame, width=8, font=("Arial", 10))
port_entry.insert(0, "5000")
port_entry.pack(side=tk.LEFT, padx=2)

#file selection
file_frame = tk.Frame(window, bg=BG_MAIN)
file_frame.pack(pady=8)

file_entry = tk.Entry(file_frame, width=40, font=("Arial", 10))
file_entry.pack(side=tk.LEFT, padx=(0, 8))

browse_btn = tk.Button(file_frame, text="Browse File", command=select_file, padx=8)
browse_btn.pack(side=tk.LEFT)

#send btn
send_btn = tk.Button(
    window, 
    text="Encrypt & Send File", 
    font=("Arial", 11, "bold"), 
    command=start_transfer,
    padx=12,
    pady=4
)
send_btn.pack(pady=8)

#status
status_label = tk.Label(
    window, 
    text="Status: Ready", 
    font=("Arial", 10, "bold"), 
    bg=BG_MAIN, 
    fg="#a6adc8"
)
status_label.pack(pady=2)


log_box = scrolledtext.ScrolledText(
    window, 
    font=("Courier", 10), 
    bg=LOG_BG, 
    fg=LOG_FG,
    height=12
)
log_box.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 20))

window.mainloop()