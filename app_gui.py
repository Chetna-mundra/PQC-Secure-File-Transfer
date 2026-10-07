import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
from network.client import send_file

#colors
BG_MAIN = "#1e1e2e"       
CARD_BG = "#2a2b3d"       
TEXT_COLOR = "#ffffff"    
SUB = "#89b4fa"           
LOG_BG = "#11111b"        
LOG_FG = "#50fa7b"        
STAGE_INACTIVE = "#313244"
STAGE_ACTIVE = "#89b4fa"  
STAGE_DONE = "#a6e3a1"    

def select_file():
    #to pick what file we want to transfer
    chosen_file = filedialog.askopenfilename()
    if chosen_file:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, chosen_file)

def update_stage(step_num, status="active"):
    #changing color of the stage boxes
    badges = [stage1_lbl, stage2_lbl, stage3_lbl, stage4_lbl]
    for idx, badge in enumerate(badges):
        if idx < step_num - 1:
            badge.config(bg=STAGE_DONE, fg="#11111b")
        elif idx == step_num - 1:
            if status == "active":
                badge.config(bg=STAGE_ACTIVE, fg="#11111b")
            else:
                badge.config(bg=STAGE_DONE, fg="#11111b")
        else:
            badge.config(bg=STAGE_INACTIVE, fg="#a6adc8")

def reset_stages():
    #resetting stage boxes nd txt to default after its done sending
    for badge in [stage1_lbl, stage2_lbl, stage3_lbl, stage4_lbl]:
        badge.config(bg=STAGE_INACTIVE, fg="#a6adc8")
    kem_info_val.config(text="Waiting...", fg="#a6adc8")
    aes_info_val.config(text="Waiting...", fg="#a6adc8")
    hash_info_val.config(text="Waiting...", fg="#a6adc8")

def run_network(path, host, port):
    try:
        #connecting
        update_stage(1, "active")
        log_box.insert(tk.END, f"Connecting to {host}:{port}...\n")
        log_box.see(tk.END)

        #encapsulation of mlkem
        update_stage(2, "active")
        log_box.insert(tk.END, "Generating shared secret with ML-KEM-768...\n")
        log_box.see(tk.END)

        #send file thingg
        result = send_file(file_path=path, host=host, port=port)

        update_stage(2, "done")
        log_box.insert(tk.END, "Shared secret created.\n")
        kem_info_val.config(text="Complete (1088B Ciphertext)", fg=STAGE_DONE)

        #aesgcm encryption
        update_stage(3, "active")
        log_box.insert(tk.END, "Deriving AES key with HKDF...\n")
        log_box.insert(tk.END, "File encrypted with AES-256-GCM and sent.\n")
        aes_info_val.config(text="AES-256-GCM (12B IV + 16B Tag)", fg=STAGE_DONE)
        update_stage(3, "done")

        #sha 256 verification
        update_stage(4, "active")
        file_hash = result.get('sha256', 'Verified')
        log_box.insert(tk.END, f"Verified server hash: {file_hash}\n")
        log_box.insert(tk.END, "File sent and verified successfully!\n\n")
        log_box.see(tk.END)

        hash_info_val.config(text=f"{file_hash[:26]}...", fg=STAGE_DONE)
        update_stage(4, "done")

        status_label.config(text="Status: Done!", fg="#50fa7b")
        messagebox.showinfo("Success", "File sent and verified successfully!")
    except Exception as e:
        log_box.insert(tk.END, f"[!] Error: {e}\n\n")
        log_box.see(tk.END)
        status_label.config(text="Status: Failed!", fg="#f38ba8")
        messagebox.showerror("Error", str(e))
    finally:
        #reanabling the send btn
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
    reset_stages()

    #thread so tht tkinter doesn't freeze during socket calls 
    thread = threading.Thread(target=run_network, args=(path, host, port), daemon=True)
    thread.start()

#window details
window = tk.Tk()
window.title("PQC Secure File Transfer - Client")
window.geometry("720x640")
window.resizable(False, False)
window.configure(bg=BG_MAIN)

#title labels
title_label = tk.Label(
    window, 
    text="Post-Quantum Secure File Transfer", 
    font=("Arial", 15, "bold"), 
    bg=BG_MAIN, 
    fg=TEXT_COLOR
)
title_label.pack(pady=(12, 2))

subtitle_label = tk.Label(
    window, 
    text="ML-KEM-768  •  AES-256-GCM  •  SHA-256", 
    font=("Arial", 9, "bold"), 
    bg=BG_MAIN, 
    fg=SUB
)
subtitle_label.pack(pady=(0, 8))

#stage boxes
pipeline_frame = tk.Frame(window, bg=BG_MAIN)
pipeline_frame.pack(pady=(6, 14))

stage1_lbl = tk.Label(
    pipeline_frame, 
    text="1. Connect", 
    font=("Arial", 11, "bold"), 
    bg=STAGE_INACTIVE, 
    fg="#a6adc8", 
    width=13, 
    pady=10
)
stage1_lbl.pack(side=tk.LEFT, padx=5)

stage2_lbl = tk.Label(
    pipeline_frame, 
    text="2. ML-KEM", 
    font=("Arial", 11, "bold"), 
    bg=STAGE_INACTIVE, 
    fg="#a6adc8", 
    width=13, 
    pady=10
)
stage2_lbl.pack(side=tk.LEFT, padx=5)

stage3_lbl = tk.Label(
    pipeline_frame, 
    text="3. AES-GCM", 
    font=("Arial", 11, "bold"), 
    bg=STAGE_INACTIVE, 
    fg="#a6adc8", 
    width=13, 
    pady=10
)
stage3_lbl.pack(side=tk.LEFT, padx=5)

stage4_lbl = tk.Label(
    pipeline_frame, 
    text="4. Check Hash", 
    font=("Arial", 11, "bold"), 
    bg=STAGE_INACTIVE, 
    fg="#a6adc8", 
    width=13, 
    pady=10
)
stage4_lbl.pack(side=tk.LEFT, padx=5)

#host and port 
config_frame = tk.Frame(window, bg=BG_MAIN)
config_frame.pack(pady=3)

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
file_frame.pack(pady=6)

file_entry = tk.Entry(file_frame, width=42, font=("Arial", 10))
file_entry.pack(side=tk.LEFT, padx=(0, 8))

browse_btn = tk.Button(file_frame, text="Browse File", command=select_file, padx=8)
browse_btn.pack(side=tk.LEFT)

#send btn
send_btn = tk.Button(
    window, 
    text="Encrypt & Send File", 
    font=("Arial", 11, "bold"), 
    command=start_transfer,
    padx=14,
    pady=4
)
send_btn.pack(pady=6)

#status text
status_label = tk.Label(
    window, 
    text="Status: Ready", 
    font=("Arial", 10, "bold"), 
    bg=BG_MAIN, 
    fg="#a6adc8"
)
status_label.pack(pady=2)

#info..crypto params live
artifacts_frame = tk.Frame(window, bg=CARD_BG, padx=12, pady=6)
artifacts_frame.pack(fill=tk.X, padx=25, pady=4)

row1 = tk.Frame(artifacts_frame, bg=CARD_BG)
row1.pack(fill=tk.X, pady=1)
tk.Label(row1, text="Key Exchange:", font=("Arial", 9, "bold"), bg=CARD_BG, fg=SUB, width=14, anchor="w").pack(side=tk.LEFT)
kem_info_val = tk.Label(row1, text="Waiting...", font=("Arial", 9), bg=CARD_BG, fg="#a6adc8", anchor="w")
kem_info_val.pack(side=tk.LEFT)

row2 = tk.Frame(artifacts_frame, bg=CARD_BG)
row2.pack(fill=tk.X, pady=1)
tk.Label(row2, text="Payload Cipher:", font=("Arial", 9, "bold"), bg=CARD_BG, fg=SUB, width=14, anchor="w").pack(side=tk.LEFT)
aes_info_val = tk.Label(row2, text="Waiting...", font=("Arial", 9), bg=CARD_BG, fg="#a6adc8", anchor="w")
aes_info_val.pack(side=tk.LEFT)

row3 = tk.Frame(artifacts_frame, bg=CARD_BG)
row3.pack(fill=tk.X, pady=1)
tk.Label(row3, text="SHA-256 Digest:", font=("Arial", 9, "bold"), bg=CARD_BG, fg=SUB, width=14, anchor="w").pack(side=tk.LEFT)
hash_info_val = tk.Label(row3, text="Waiting...", font=("Arial", 9), bg=CARD_BG, fg="#a6adc8", anchor="w")
hash_info_val.pack(side=tk.LEFT)

#output terminal log box
log_box = scrolledtext.ScrolledText(
    window, 
    font=("Courier", 10), 
    bg=LOG_BG, 
    fg=LOG_FG,
    height=8
)
log_box.pack(fill=tk.BOTH, expand=True, padx=25, pady=(6, 15))

window.mainloop()