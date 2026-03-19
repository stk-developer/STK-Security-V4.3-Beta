import customtkinter as ctk
import os, shutil, json, hashlib, threading, math, subprocess
from tkinter import messagebox, filedialog
from collections import Counter

# --- Ayarlar ---
CONFIG = {
    "QUARANTINE_DIR": "./STK_Vault",
    "THREAT_LIMIT": 8, # Skoru biraz artırdık (Defender'a güveniyoruz)
    "DEFENDER_PATH": r"C:\Program Files\Windows Defender\MpCmdRun.exe"
}

class STKSecurity(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("STK Security V4.3 Beta")
        self.geometry("1000x650")
        ctk.set_appearance_mode("dark")
        
        if not os.path.exists(CONFIG["QUARANTINE_DIR"]): os.makedirs(CONFIG["QUARANTINE_DIR"])
        self.threat_report = []
        self.build_ui()

    def build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # --- Yan Panel ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1a1a1a")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="STK SECURITY", font=("Segoe UI", 22, "bold"), text_color="#00bcd4").pack(pady=30)
        
        self.status_label = ctk.CTkLabel(self.sidebar, text="SİSTEM GÜVENDE", font=("Arial", 14, "bold"), text_color="#00FF7F")
        self.status_label.pack(pady=10)

        ctk.CTkButton(self.sidebar, text="Hızlı Tarama", command=lambda: self.start_audit("quick"), fg_color="#2b2b2b").pack(pady=10, padx=20, fill="x")
        ctk.CTkButton(self.sidebar, text="Tam Tarama", command=lambda: self.start_audit("full"), fg_color="#2b2b2b").pack(pady=10, padx=20, fill="x")
        ctk.CTkButton(self.sidebar, text="Dosya Seç ve Tara", command=lambda: self.start_audit("file"), fg_color="#2b2b2b").pack(pady=10, padx=20, fill="x")
        
        # --- Ana Ekran ---
        self.main_view = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_view.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.info_label = ctk.CTkLabel(self.main_view, text="STK Analiz Motoru + Windows Defender Shield Aktif", font=("Arial", 14))
        self.info_label.pack(pady=15)

        self.prog = ctk.CTkProgressBar(self.main_view, progress_color="#00bcd4")
        self.prog.pack(fill="x", padx=40, pady=10)
        self.prog.set(0)

        self.log = ctk.CTkTextbox(self.main_view, font=("Consolas", 12), fg_color="#1e1e1e")
        self.log.pack(fill="both", expand=True, padx=20, pady=20)
        self.log.tag_config("danger", foreground="#FF3131")
        self.log.tag_config("safe", foreground="#00FF7F")

    def get_entropy(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read(1024 * 1024) # İlk 1MB'ı oku
                if not data: return 0
                counts = Counter(data)
                return -sum((cnt/len(data)) * math.log2(cnt/len(data)) for cnt in counts.values())
        except: return 0

    def check_with_defender(self, path):
        """Windows Defender'ı gizli modda çalıştırıp dosyayı sorar."""
        try:
            cmd = [CONFIG["DEFENDER_PATH"], "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]
            # creationflags=0x08000000 -> Pencere açılmasını engeller
            res = subprocess.run(cmd, capture_output=True, text=True, creationflags=0x08000000)
            return res.returncode == 2 # 2 kodu 'Tehdit Bulundu' demektir
        except: return False

    def start_audit(self, mode):
        targets = []
        if mode == "quick": targets = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
        elif mode == "full": targets = [d + ":\\" for d in "CDEFG" if os.path.exists(d + ":\\")]
        elif mode == "file":
            f = filedialog.askopenfilename()
            if f: targets = [f]

        if targets:
            self.threat_report = []
            self.log.delete("1.0", "end")
            self.status_label.configure(text="TARANIYOR...", text_color="#FFAC1C")
            threading.Thread(target=self.run_engine, args=(targets,), daemon=True).start()

    def run_engine(self, targets):
        files_to_scan = []
        for t in targets:
            if os.path.isfile(t): files_to_scan.append(t)
            else:
                for r, d, fs in os.walk(t):
                    for f in fs: files_to_scan.append(os.path.join(r, f))
        
        total = len(files_to_scan)
        for i, f_path in enumerate(files_to_scan):
            if i % 5 == 0: self.after(0, lambda v=(i+1)/total, n=os.path.basename(f_path): self.ui_up(v, n))
            
            ent = self.get_entropy(f_path)
            ext = os.path.splitext(f_path)[1].lower()
            
            # --- STK Sezgisel Analiz ---
            score = 0
            if ext in [".exe", ".dll", ".bin"]: score += 4
            if ent > 7.5: score += 5
            
            # Eğer skor yüksekse (9 gibi), Defender'a son sözü sor
            if score >= CONFIG["THREAT_LIMIT"]:
                self.after(0, lambda n=os.path.basename(f_path): self.log.insert("end", f"🔍 {n} inceleniyor...\n"))
                
                is_virus = self.check_with_defender(f_path)
                
                if is_virus:
                    self.threat_report.append(f_path)
                    self.after(0, lambda n=os.path.basename(f_path): self.log.insert("end", f"🚨 TEHLİKE ONAYLANDI: {n}\n", "danger"))
                else:
                    self.after(0, lambda n=os.path.basename(f_path): self.log.insert("end", f"✅ False Positive: {n} (Defender Güveniyor)\n", "safe"))

        self.after(0, lambda: self.finish())

    def ui_up(self, v, n):
        self.prog.set(v)
        self.info_label.configure(text=f"Analiz: {n[:30]}...")

    def finish(self):
        if self.threat_report:
            self.status_label.configure(text="TEHDİT VAR!", text_color="#FF3131")
            if messagebox.askyesno("Karantina", f"{len(self.threat_report)} gerçek tehdit bulundu. Karantinaya alınsın mı?"):
                for t in self.threat_report:
                    try: shutil.move(t, os.path.join(CONFIG["QUARANTINE_DIR"], os.path.basename(t) + ".stk"))
                    except: pass
                messagebox.showinfo("Başarılı", "Tehditler STK_Vault'a hapsedildi.")
        else:
            self.status_label.configure(text="SİSTEM GÜVENDE", text_color="#00FF7F")
            messagebox.showinfo("STK Security", "Tarama tertemiz! (AnyDesk ve Rufus artık güvende 😏)")

if __name__ == "__main__":
    app = STKSecurity()
    app.mainloop()
