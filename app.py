from tkinter import *
from tkinter import filedialog, messagebox, ttk
from tkinter import font
from detect_malware import Scanner  # Nhập class Scanner từ detect_malware.py
# from ttkthemes import ThemedTk

class VirusScannerApp:
    def __init__(self, app):
        self.app = app
        self.app.title("Ứng Dụng Quét Virus Đơn Giản")
        self.app.minsize(height=600, width=900)
        self.app.geometry("900x600")
        # self.app.configure(bg="#E6F7FF")

        self.folder_path = StringVar()
        self.rules_directory = r'./data_rule'  # Đường dẫn đến thư mục quy tắc YARA
        self.scanner = Scanner(self.rules_directory)  # Khởi tạo Scanner

        # Sử dụng Theme forest-light: https://github.com/rdbende/Forest-ttk-theme?tab=readme-ov-file
        style = ttk.Style(self.app)
        self.app.call("source", "F:/TUHOCTAP/TKINTER/APP_CDCN/forest-light.tcl")
        style.theme_use("forest-light")

        self.create_widgets()
    
    # -------------------------Chức năng giao diện phụ--------------------------
    # Hàm thêm placeholder
    def add_placeholder(self, entry, placeholder_text):
        entry.insert(0, placeholder_text)
        
        def on_focus_in(event):
            if entry.get() == placeholder_text:
                entry.delete(0, END)

        def on_focus_out(event):
            if entry.get() == "":
                entry.insert(0, placeholder_text)
        
        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
       
    def create_widgets(self):
        # FRAME 1:
        container = ttk.Frame(self.app)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # Đặt trọng số cho container, chỉ có 1 hàng và 2 cột
        container.grid_rowconfigure(0, weight=2)
        container.grid_rowconfigure(1, weight=7)
        container.grid_rowconfigure(2, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        ##------------------------------Sidebar---------------------------------
        sidebar_f1 = ttk.Frame(container)
        sidebar_f1.grid(row=0, column=0, sticky="nsew", padx=5)

        sidebar_f1.grid_columnconfigure(0, weight=7)
        sidebar_f1.grid_columnconfigure(1, weight=1)
        sidebar_f1.grid_columnconfigure(2, weight=1)

        # Ô lấy đường dẫn thư mục
        entry_path = ttk.Entry(sidebar_f1, textvariable=self.folder_path)
        entry_path.grid(row=0, column=0, sticky="we", padx=5)

        # Button upload:
        browse_button = ttk.Button(sidebar_f1, text="Chọn thư mục", command=self.browse_folder)
        browse_button.grid(row=0, column=1, sticky="we", padx=5)

        # Button scan
        scan_button = ttk.Button(sidebar_f1, text="Quét", style='Accent.TButton', command=self.scan_folder)
        scan_button.grid(row=0, column=2, sticky="we", padx=5)

        # Thêm placeholder vào ô nhập
        self.add_placeholder(entry_path, "F:\TUHOCTAP\MALWARE")
        ##-------------------------Khung làm việc chính----------------------------
        main_work = ttk.LabelFrame(container, text="Dashboard")
        main_work.grid(row=1, column=0, sticky="nsew")

        main_work.grid_rowconfigure(0, weight=4)
        main_work.grid_rowconfigure(1, weight=5)
        main_work.grid_rowconfigure(2, weight=1)
        main_work.grid_columnconfigure(0, weight=1)
        main_work.grid_columnconfigure(1, weight=9)

        # Tạo một font mới với cỡ chữ lớn và in đậm
        bold_font = font.Font(size=40, weight="bold")
        self.label_total = ttk.Label(main_work, text="20/100", font=bold_font, foreground='red', justify="center")
        self.label_total.grid(row=0, column=0,  padx=10, pady=10)

        # Bảng thống kê:
        # Treeview
        columnsname2 = ("type_malware", "count")
        self.treeview_type = ttk.Treeview(main_work, selectmode="extended", columns=columnsname2, height=5, show="headings")
        self.treeview_type.grid(row=0, column=1, sticky="nsew",  padx=10, pady=20)
        self.treeview_type.heading("type_malware", text="Loại mã độc")
        self.treeview_type.heading("count", text="Số lượng")
        self.treeview_type.column("type_malware", anchor="w", width=int(300))
        self.treeview_type.column("count", anchor="center", width=int(50))

        # Bảng xem phát hiện
        columnsname = ("path", "virus_name")
        self.treeview_file = ttk.Treeview(main_work, selectmode="extended", height=10, columns=columnsname, show="headings")
        self.treeview_file.grid(row=1, column=0, columnspan=2, sticky="nsew",  padx=10)
        self.treeview_file.heading("path", text="Đường dẫn")
        self.treeview_file.heading("virus_name", text="Tên mã độc")
        self.treeview_file.column("path", anchor="w", width=int(800*0.8))
        self.treeview_file.column("virus_name", anchor="center", width=int(800*0.2))

        # Xem khi chạy:
        self.current_file_label = ttk.Label(main_work, text='Đang quét file: ', foreground='blue')
        self.current_file_label.grid(row=2, column=0, columnspan=2, padx=30, sticky="we", pady=10)

        # self.app.eval('tk::PlaceWindow . center')

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)

    def add_to_treeview(self, file_path, virus_name):
        """Thêm tệp độc hại vào Treeview."""
        self.treeview_file.insert("", END, values=(file_path, virus_name))

    def add_total_view(self, type_malware, num):
        self.treeview_type.insert("", END, values=(type_malware, num))

    def total_label_change(self, total, num_files):
        self.label_total.config(text=f"{total}/{num_files}")
        self.label_total.update_idletasks()
        self.label_total.master.update()

    def scan_folder(self):
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn thư mục để quét.")
            return
        
        # Xóa dữ liệu cũ trong Treeview
        for item in self.treeview_file.get_children():
            self.treeview_file.delete(item)

        for item in self.treeview_type.get_children():
            self.treeview_type.delete(item)
        
        self.total_label_change("...", "...")
        
        # Quét thư mục
        self.scanner.scan_directory(folder, self.current_file_label, self.add_to_treeview, self.add_total_view, self.total_label_change)

if __name__ == "__main__":
    root = Tk()
    app = VirusScannerApp(root)
    root.mainloop()
