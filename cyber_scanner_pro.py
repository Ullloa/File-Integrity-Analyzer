import os
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
import time

class CyberShield:
    """
    Final Portfolio Version: Advanced File Identification & Audit Tool.
    Focuses on detecting malicious extension spoofing (malware evasion).
    """
    
    SIGNATURES = {
        "JPEG Image": ["FF", "D8", "FF"],
        "PNG Image": ["89", "50", "4E", "47"],
        "PDF Document": ["25", "50", "44", "46"],
        "Windows Executable (EXE)": ["4D", "5A"],
        "ZIP Archive": ["50", "4B", "03", "04"],
        "Java Class File": ["CA", "FE", "BA", "BE"],
        "ELF Linux Executable": ["7F", "45", "4C", "46"],
        "RAR Archive": ["52", "61", "72", "21", "1A", "07"]
    }

    def get_header(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return [f"{b:02X}" for b in f.read(16)]
        except Exception:
            return None

    def analyze_item(self, path):
        header = self.get_header(path)
        filename = os.path.basename(path)
        ext = os.path.splitext(filename)[1].upper().replace(".", "")
        
        detected = "Unknown"
        for name, sig in self.SIGNATURES.items():
            if header and header[:len(sig)] == sig:
                detected = name
                break
        
        is_spoofed = False
        if detected != "Unknown":
            if not (ext in detected or (ext == "JPG" and "JPEG" in detected)):
                is_spoofed = True
        
        # Formatting for UI
        status_icon = " [!] SPOOFED " if is_spoofed else " [OK] "
        return {
            "is_spoofed": is_spoofed,
            "text": f"{status_icon} | {filename[:25]:<25} | Declared: {ext:<5} | Real: {detected}",
            "filename": filename
        }

def print_banner():
    print("\n" + "█"*60)
    print("      🛡️   CYBERSHIELD AUDIT TOOL - V1.0  🛡️")
    print("█"*60)
    print(" 1. Analyze Single File      2. Audit Folder      3. Exit")
    print("█"*60)

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    shield = CyberShield()

    while True:
        print_banner()
        choice = input("\n> Select action: ")

        if choice == '1':
            file_path = filedialog.askopenfilename()
            if file_path:
                print("\n[*] Inspecting file header...")
                time.sleep(0.5)
                result = shield.analyze_item(file_path)
                print(result["text"])
            
        elif choice == '2':
            folder_path = filedialog.askdirectory()
            if folder_path:
                print(f"\n[*] Auditing directory: {folder_path}")
                files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
                
                mismatches = []
                # Progress simulation
                for i, f in enumerate(files):
                    progress = int((i + 1) / len(files) * 20)
                    print(f"\rProgress: [{'#' * progress}{'.' * (20 - progress)}] {i+1}/{len(files)}", end="")
                    time.sleep(0.1)
                    
                    res = shield.analyze_item(os.path.join(folder_path, f))
                    if res["is_spoofed"]:
                        mismatches.append(res["text"])
                
                print("\n\n--- AUDIT RESULTS ---")
                if not mismatches:
                    print("✅ No spoofed files detected in this directory.")
                else:
                    print(f"❌ WARNING: {len(mismatches)} spoofed files identified!")
                    for m in mismatches: print(m)
                
                # Save report
                with open("audit_report.txt", "w", encoding="utf-8") as rep:
                    rep.write(f"CyberShield Audit - {datetime.now()}\n\n" + "\n".join(mismatches))
                print("\n[+] Report saved to 'audit_report.txt'")

        elif choice == '3':
            print("System offline. Stay secure.")
            break