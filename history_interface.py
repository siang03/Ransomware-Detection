import sys, os, json, subprocess, logging
# Import and configure logging
import log_config
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QComboBox, QDateTimeEdit,
    QTableWidget, QTableWidgetItem, QPushButton, QSizePolicy, QAbstractItemView, QHeaderView, QFrame
)
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtCore import Qt, QFileSystemWatcher, QTimer, QDateTime
from datetime import datetime

logger = logging.getLogger(__name__)

# history file path
HISTORY_FILE = os.path.join(os.getcwd(), "history.json")

class HistoryInterface(QWidget):
    def __init__(self):
        super().__init__()
        self.code_watcher = QFileSystemWatcher()
        self.logo_path = "/home/kali/Desktop/FYPGUI/assets/gui/image_1.png"
        self.setWindowTitle("RansomSpy")
        self.setStyleSheet("background-color: #57e1f7;")
        self.setGeometry(350, 40, 1080, 832)
        self.setupCodeWatcher()

        self.current_page = 0
        self.records_per_page = 10
        self.history = []
        self.filtered_history = None   

        # Main vertical layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Header: original logo + title
        hdr = QHBoxLayout()
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label = QLabel()
        # restore original dimensions
        self.loadLogo()
        self.title = QLabel("RansomSpy")
        self.title.setFont(QFont("Inter", 60, QFont.Weight.ExtraBold))
        self.title.setStyleSheet("color: black;")
        hdr.addWidget(self.logo_label)
        hdr.addSpacing(10)
        hdr.addWidget(self.title)
        main_layout.addLayout(hdr)
        
        # Second Layout
        second_layout = QVBoxLayout()

        self.subtitle = QLabel("Review RansomSpy Previous Detections", self)
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setStyleSheet("color: black; font-size: 20px; font-weight: 500;")

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setStyleSheet("color: black; background-color: black; height: 1px;")
        line.setFixedWidth(790)
        second_layout.addWidget(self.subtitle, alignment=Qt.AlignmentFlag.AlignCenter)
        second_layout.addWidget(line, alignment=Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)

        main_layout.addLayout(second_layout)
        # Time Filter Bar
        time_filter_layout = QHBoxLayout()
        time_filter_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        time_filter_layout.addWidget(QLabel("From:"))
        self.from_dt = QDateTimeEdit(self)
        self.from_dt.setStyleSheet("color: black;")
        self.from_dt.setCalendarPopup(True)
        # default to 24h ago:
        self.from_dt.setDateTime(QDateTime.currentDateTime().addDays(-1))
        time_filter_layout.addWidget(self.from_dt)

        time_filter_layout.addSpacing(20)
        time_filter_layout.addWidget(QLabel("To:"))
        self.to_dt   = QDateTimeEdit(self)
        self.to_dt.setStyleSheet("color: black;")
        self.to_dt.setCalendarPopup(True)
        self.to_dt.setDateTime(QDateTime.currentDateTime())
        time_filter_layout.addWidget(self.to_dt)

        time_filter_layout.addSpacing(20)
        self.apply_btn = QPushButton("Apply", self)
        self.apply_btn.setStyleSheet("QPushButton { color: black; }")
        self.apply_btn.clicked.connect(self.filter_all)
        time_filter_layout.addWidget(self.apply_btn)
        
        main_layout.addLayout(time_filter_layout)
        
        # — FILTER BAR —
        filter_layout = QHBoxLayout()
        filter_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        #  filename filter
        self.name_filter = QLineEdit()
        self.name_filter.setStyleSheet("color: black;")
        self.name_filter.setPlaceholderText("Filter by file name…")
        self.name_filter.textChanged.connect(self.filter_all)
        filter_layout.addWidget(QLabel("File:"))
        filter_layout.addWidget(self.name_filter)

        #  prediction filter
        self.pred_filter = QComboBox()
        self.pred_filter.addItems(["All", "Ransomware", "Benign"])
        self.pred_filter.setStyleSheet("QComboBox { color: black; }")
        # ensure it matches your main bg color and text stays legible

        self.pred_filter.currentIndexChanged.connect(self.filter_all)
        filter_layout.addSpacing(20)
        filter_layout.addWidget(QLabel("Prediction:"))
        filter_layout.addWidget(self.pred_filter)
        
        # in your __init__(), after you build name_filter and pred_filter, add:
        self.reset_btn = QPushButton("Reset Filters")
        self.reset_btn.setStyleSheet("QPushButton { color: black; }")
        self.reset_btn.clicked.connect(self.reset_filters)
        filter_layout.addSpacing(20)
        filter_layout.addWidget(self.reset_btn)

        main_layout.addLayout(filter_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["No.", "Time", "File", "Prediction"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        
        self.table.setStyleSheet("QTableWidget { color: black; }")

        header = self.table.horizontalHeader()
        header.setStyleSheet("QHeaderView::section { color: black; }")
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        #self.table.setAlternatingRowColors(True)
        
        # ===== hide the default row-header numbers =====
        self.table.verticalHeader().setVisible(False)
        
        main_layout.addWidget(self.table)
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Pagination controls
        pg_layout = QHBoxLayout()
        pg_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.prev_btn = QPushButton("Previous")
        self.prev_btn.clicked.connect(self.prev_page)
        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.next_page)
        self.page_label = QLabel("Page 1")
        self.page_label.setFont(QFont("Inter", 12))
        pg_layout.addWidget(self.prev_btn)
        pg_layout.addSpacing(20)
        pg_layout.addWidget(self.page_label)
        pg_layout.addSpacing(20)
        pg_layout.addWidget(self.next_btn)
        main_layout.addLayout(pg_layout)

        # Back & Home button
        btn_layout = QHBoxLayout()
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.home_button = QPushButton("Exit", self)
        self.home_button.setFixedSize(150, 40)
        self.home_button.clicked.connect(self.switchToUploadFile)
        btn_layout.addWidget(self.home_button)
        btn_layout.addSpacing(20)
        self.back_btn = QPushButton("View Result")
        self.back_btn.setFixedSize(150, 40)
        self.back_btn.setStyleSheet("QPushButton { color: black; }")
        self.back_btn.clicked.connect(self.on_back)
        btn_layout.addWidget(self.back_btn)
        main_layout.addLayout(btn_layout)

        # load and show
        self.load_history()
        self.show_page()
    
    def switchToUploadFile(self):
        python = sys.executable
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upload_file_interface.py")
        logger.info("result_interface: Switching to upload_file_interface.py")
        subprocess.Popen([python, script_path])

        # Close the current GUI
        self.close()
        sys.exit(0)
    
    def loadLogo(self):
        if os.path.exists(self.logo_path):
            pix = QPixmap(self.logo_path).scaled(223, 242, Qt.AspectRatioMode.KeepAspectRatio)
            self.logo_label.setPixmap(pix)
            logger.info("Logo loaded from %s", self.logo_path)
        else:
            logger.error("Logo file not found: %s", self.logo_path)

    def load_history(self):
        if not os.path.exists(HISTORY_FILE):
            self.history = []
            return
        try:
            with open(HISTORY_FILE) as f:
                self.history = json.load(f)
                print('history ', self.history)
        except Exception as e:
            logger.error("Failed loading history: %s", e)
            self.history = []
            
         # initialize filtered list to the full history
        self.filtered_history = self.history[:]

    def show_page(self):
        # first, clear any previous spans or leftover cells
        self.table.clearSpans()
        self.table.clearContents()
        
        # if the user has no history at all:
        if not self.history:
            self.table.clearContents()
            self.table.setRowCount(1)
            item = QTableWidgetItem("ℹ️  No detection history available.")
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setSpan(0, 0, 1, self.table.columnCount())
            self.table.setItem(0, 0, item)

            # disable paging controls
            self.page_label.setText("Page 0/0")
            self.prev_btn.setEnabled(False)
            self.next_btn.setEnabled(False)

            # shrink to exactly one row
            row_h    = self.table.verticalHeader().defaultSectionSize()
            header_h = self.table.horizontalHeader().height()
            self.table.setMaximumHeight(header_h + row_h + 2)
            return
            
        # pick the source list (filtered if non‐empty, else full history)
        source = self.filtered_history if self.filtered_history is not None else self.history

        # if filter produced no results:
        if not source:
            self.table.clearContents()
            self.table.setRowCount(1)
            item = QTableWidgetItem("⚠️  No records match your filters.")
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setSpan(0, 0, 1, self.table.columnCount())
            self.table.setItem(0, 0, item)

            # disable paging controls
            self.page_label.setText("Page 0/0")
            self.prev_btn.setEnabled(False)
            self.next_btn.setEnabled(False)

            # shrink to exactly one row
            row_h    = self.table.verticalHeader().defaultSectionSize()
            header_h = self.table.horizontalHeader().height()
            self.table.setMaximumHeight(header_h + row_h + 2)
            return
            
        start  = self.current_page * self.records_per_page
        end    = min(start + self.records_per_page, len(source))
        subset = source[start:end]

        self.table.setRowCount(len(subset))
        for i, rec in enumerate(subset, start=1):
            r   = i - 1
            idx = start + i
            self.table.setItem(r, 0, QTableWidgetItem(str(idx)))
            self.table.setItem(r, 1, QTableWidgetItem(rec.get("timestamp", "")))
            self.table.setItem(r, 2, QTableWidgetItem(os.path.basename(rec.get("file_path", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(rec.get("prediction", "")))

        # recalc total pages against the filtered set
        total_pages = ((len(source) - 1) // self.records_per_page + 1) if source else 1
        self.page_label.setText(f"Page {self.current_page+1}/{total_pages}")
        self.prev_btn.setEnabled(self.current_page > 0)
        self.next_btn.setEnabled(end < len(source))
        
        # recalc height so no empty gap
        row_h    = self.table.verticalHeader().defaultSectionSize()
        header_h = self.table.horizontalHeader().height()
        rows     = self.table.rowCount()
        self.table.setMaximumHeight(header_h + rows * row_h + 2)

    def next_page(self):
        if (self.current_page+1)*self.records_per_page < len(self.history):
            self.current_page += 1
            self.show_page()

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.show_page()
            
    def filter_all(self):
        # 1) Read UI state
        start_dt = self.from_dt.dateTime().toPyDateTime()
        end_dt   = self.to_dt  .dateTime().toPyDateTime()
        name_sub = self.name_filter.text().strip().lower()
        pred_txt = self.pred_filter.currentText()        # "All", "Ransomware", "Benign"

        # 2) Begin with the full history
        src = self.history

        # 3) Time filter
        def in_time(rec):
            try:
                ts = datetime.strptime(rec["timestamp"], "%Y-%m-%d %H:%M:%S")
                return start_dt <= ts <= end_dt
            except:
                return False
        src = [r for r in src if in_time(r)]

        # 4) Name substring filter
        if name_sub:
            src = [r for r in src if name_sub in r["file_path"].lower()]

        # 5) Prediction filter
        if pred_txt != "All":
            src = [r for r in src if r["prediction"] == pred_txt]

        # 6) Commit & redraw
        self.filtered_history = src
        self.current_page = 0
        self.show_page()
        
    def reset_filters(self):
        # clear the text filter
        self.name_filter.clear()
        # reset the combo back to “All”
        self.pred_filter.setCurrentIndex(0)   # assuming 0 == “All”
        # reset the time filters
        self.from_dt.setDateTime(QDateTime.currentDateTime().addDays(-1))
        self.to_dt  .setDateTime(QDateTime.currentDateTime())
        # reapply to show everything
        self.filter_all()

    def on_back(self):
        # see if there is an actual selected row
        selected = self.table.selectionModel().selectedRows()
        if selected:
            # grab the first selected row’s index
            row = selected[0].row()
        else:
            # no selection → use last entry
            row = None

        # calculate the global index into self.history
        if row is None:
            global_index = len(self.history) - 1
        else:
            global_index = self.current_page * self.records_per_page + row

        # sanity check
        if not (0 <= global_index < len(self.history)):
            return

        rec = self.history[global_index]
        file_path = rec.get("file_path", "")
        prediction = rec.get("prediction", "")
        # map back to R/G
        letter = "R" if prediction.lower().startswith("r") else "G"

        python = sys.executable
        script = os.path.join(os.path.dirname(__file__), "result_interface.py")
        subprocess.Popen([python, script, letter, file_path])
        self.close()
        sys.exit(0)

    def setupCodeWatcher(self):
        path = os.path.abspath(__file__)
        if os.path.exists(path):
            self.code_watcher.addPath(path)
            self.code_watcher.fileChanged.connect(self.restartApp)
            logger.info("Code watcher set for %s", path)

    def restartApp(self):
        QTimer.singleShot(1000, self.relaunch)

    def relaunch(self):
        python = sys.executable
        script = os.path.abspath(__file__)
        subprocess.Popen([python, script])
        sys.exit(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QLabel, QPushButton {
            color: black;
        }
    """)
    win = HistoryInterface()
    win.show()
    sys.exit(app.exec())
