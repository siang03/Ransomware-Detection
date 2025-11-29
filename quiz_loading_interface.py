import sys
import os
import subprocess
import joblib
import logging
import json
import random
import pandas as pd
import datetime

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, 
    QSpacerItem, QSizePolicy, QFrame, QProgressBar, QMessageBox, QPushButton, QButtonGroup, QRadioButton, QStyle
)
from PyQt6.QtGui import QPixmap, QFont, QTransform, QPainter
from PyQt6.QtCore import Qt, QFileSystemWatcher, QTimer, QThread, pyqtSignal
from file_behavior_analysis import fetch_cuckoo_report
from file_behavior_analysis import check_task_status as original_check_task_status
from upload_file_interface import RansomSpyGUI

# Import common logging configuration
import log_config

logger = logging.getLogger(__name__)

HISTORY_FILE = os.path.expanduser("~/Desktop/FYPGUI/history.json")

def record_history(file_path, result):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(sep=' ', timespec='seconds'),
        "file_path": file_path,                      
        "prediction": "Ransomware" if result == "R" else "Benign"
    }

    # read existing history (if valid JSON), else start fresh
    data = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, ValueError):
            data = []      # empty or invalid JSON → treat as no history

    # append & write back
    data.append(entry)
    with open(HISTORY_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def check_task_status_wrapper(task_id, window):
    try:
        # Call the original check_task_status function
        return original_check_task_status(task_id)
    except Exception as e:
        # Handle the exception and show the error dialog
        error_message = f"Error during analysis status check: {str(e)}"
        logger.error(error_message)
        window.show_error_dialog(error_message)
        return False

def show_centered_message(parent, title, message, icon=QMessageBox.Icon.Information):
    msg = QMessageBox(parent)
    msg.setIcon(icon)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    msg.setWindowModality(Qt.WindowModality.ApplicationModal)

    # Ensure it's sized before centering
    msg.adjustSize()
    screen = QApplication.primaryScreen().availableGeometry()
    size = msg.sizeHint()
    x = (screen.width() - size.width()) // 2
    y = (screen.height() - size.height()) // 2
    msg.move(x, y)

    msg.exec()
    
# 🟢 STEP 1: Define the Worker Thread (Before GUI Class)
class AnalysisWorker(QThread):
    progress_updated = pyqtSignal(int)  # Emit progress updates
    analysis_complete = pyqtSignal(str)    # Emit when analysis is complete
    stop_timer_signal = pyqtSignal()

    def __init__(self, task_id, file_path, window):
        super().__init__()
        self.task_id = task_id
        self.file_path = file_path
        self.window = window
        logger.info("AnalysisWorker initialized with Task ID: %s", task_id)

    def run(self):
        progress = 0
        while progress < 90:
            task_completed = check_task_status_wrapper(self.task_id, self.window)  # Backend function
            if task_completed:
                self.progress_updated.emit(100)  # Immediately finish progress
                logger.info("Task %s completed successfully", self.task_id)
                break
                
            # If task check encountered an error, stop the loop
            elif task_completed is False:
                logger.error("Task %s failed during status check", self.task_id)
                break
                
            progress += 5
            logger.info("Progress for Task ID %s updated: %s%%", self.task_id, progress)
            self.progress_updated.emit(progress)
            self.progress_updated.emit(progress)
            self.msleep(1000)    # Simulate waiting for response

        # Once done, fetch the report
        csv_file_path = fetch_cuckoo_report(self.task_id, self.file_path)
        
        if not csv_file_path:
            logger.error("❌ Failed to fetch or process the Cuckoo report.")
            show_centered_message(self, "Error", "Failed to fetch or process the Cuckoo report.", QMessageBox.Icon.Critical)
            return  # Stop further execution
            
        logger.info("CSV File generated: %s", csv_file_path)
        self.analysis_complete.emit(csv_file_path)  # Notify GUI
        

class RansomSpyGUI(QWidget):
    def __init__(self, task_id, file_path):
        super().__init__()
        self.logo_path = "/home/kali/Desktop/FYPGUI/assets/gui/image_1.png"
        self.gear_path = "/home/kali/Desktop/FYPGUI/assets/gui/gear1.svg"
        self.code_watcher = QFileSystemWatcher()
        self.task_id = task_id
        self.file_path = file_path
        self.quiz_index = -1
        self.mode = "fact"        # will cycle: fact → question → result
        self.load_quiz_data()

        self.initUI()
        self.setupCodeWatcher()
        self.startGearAnimation()
        self.start_analysis()
        logger.info("quiz_loading_interface: Initialized with Task ID: %s, File Path: %s", task_id, file_path)
    
    def load_quiz_data(self):
        quiz_file = os.path.join(os.path.dirname(__file__), 'quiz_data.json')

        try:
            with open(quiz_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error("Error loading quiz data: %s", e)
            show_centered_message(self, "Error", "Failed to load quiz data. Please check the JSON file.", QMessageBox.Icon.Critical)
            self.quiz_data = []
            return

        # Empty file check
        if not data:
            logger.warning("Quiz file is empty.")
            show_centered_message(self, "No Quiz Data", "The quiz file is empty. Please add questions.", QMessageBox.Icon.Warning)
            self.quiz_data = []
            return

        # ✅ Validate question structure
        valid_data = []
        for q in data:
            if (
                isinstance(q, dict) and
                'question' in q and
                'options' in q and
                'answer' in q and
                'info' in q and
                isinstance(q['options'], list) and
                len(q['options']) >= 2 and
                isinstance(q['answer'], int) and
                0 <= q['answer'] < len(q['options'])
            ):
                valid_data.append(q)

        if not valid_data:
            QMessageBox.critical(self, "Invalid Quiz Format", "No valid quiz entries were found. Please check the file format.")
            self.quiz_data = []
            return

        # ✅ Shuffle questions and re-map answers
        random.shuffle(valid_data)
        for q in valid_data:
            opts = q['options']
            correct_text = opts[q['answer']]
            random.shuffle(opts)
            q['options'] = opts
            q['answer'] = opts.index(correct_text)

        # ✅ Store the validated, shuffled quiz
        self.quiz_data = valid_data
        logger.info("Loaded %d valid quiz items", len(self.quiz_data))

    def initUI(self):
        self.setWindowTitle("RansomSpy")
        self.setStyleSheet("background-color: #57e1f7;")
        self.setGeometry(350, 40, 1080, 882)
        
        # 1) Instantiate quiz widgets **first**:
        self.quiz_info = QLabel('', self)
        self.quiz_info.setFont(QFont('Inter', 12))
        self.quiz_info.setStyleSheet("color: black;")
        self.quiz_info.setWordWrap(True)
        self.quiz_info.setMaximumHeight(150)   # 150px tall at most
        
        self.question_label = QLabel('', self)
        self.question_label.setFont(QFont('Inter', 14, QFont.Weight.Bold))
        self.question_label.setStyleSheet("color: black;")
        self.question_label.setWordWrap(True)
        self.question_label.setMaximumHeight(200) 
        self.question_label.hide()

        self.options_group   = QButtonGroup(self)
        self.option_buttons  = []
        for i in range(4):
            rb = QRadioButton(self)
            rb.setStyleSheet("color: black;")
            rb.hide()
            self.options_group.addButton(rb, i)
            self.option_buttons.append(rb)

        self.submit_btn = QPushButton('Submit', self)
        forward_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowForward)
        self.submit_btn.setIcon(forward_icon)
        self.submit_btn.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.submit_btn.setStyleSheet("""
            QPushButton {
                background-color: lightgray;
                color: black;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;

                border: 2px solid #A9A9A9;
                padding: 8px;
                min-width: 60px;
            }
            QPushButton:hover {
                background-color: #B0B0B0;
                color: white;
                border: 2px solid #808080;
            }
            QPushButton:pressed {
                background-color: gray;
                border: 2px solid #606060;
            }
        """)
        self.submit_btn.clicked.connect(self.on_quiz_button)
        self.submit_btn.hide()
        
        self.back_btn = QPushButton('Back', self)
        backward_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack)
        self.back_btn.setIcon(backward_icon)

        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: lightgray;
                color: black;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;
                border: 2px solid #A9A9A9;
                padding: 6px;
                min-width: 60px;
            }
            QPushButton:hover { 
                background-color: #B0B0B0; 
                color: white; 
                border: 2px solid #808080;
            }
            QPushButton:pressed { 
                background-color: gray;
                border: 2px solid #606060;
            }
        """)
        self.back_btn.clicked.connect(self.on_back_button)
        self.back_btn.hide()
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Logo and Title
        top_layout = QHBoxLayout()
        top_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.logo_label = QLabel(self)
        self.loadLogo()

        spacer = QSpacerItem(10, 10, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.title = QLabel("RansomSpy", self)
        self.title.setFont(QFont("Inter", 60, QFont.Weight.ExtraBold))
        self.title.setStyleSheet("color: black;")

        top_layout.addWidget(self.logo_label, alignment=Qt.AlignmentFlag.AlignVCenter)
        top_layout.addItem(spacer)
        top_layout.addWidget(self.title, alignment=Qt.AlignmentFlag.AlignVCenter)
        main_layout.addLayout(top_layout)

        # Subtitle
        second_layout = QVBoxLayout()
        self.subtitle = QLabel("Analyse suspicious files to detect ransomware", self)
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

        # Quiz
        # Quiz / Info container (white, semi‑transparent card)
        # 3) Create & style the quiz_frame **after** your widgets exist:
        quiz_frame = QFrame()
        quiz_frame.setFrameShape(QFrame.Shape.StyledPanel)
        quiz_frame.setMinimumWidth(800)
        quiz_frame.setStyleSheet("""
            background-color: rgba(255,255,255,200);
            border-radius: 10px;
            padding: 12px;
        """)
        # only expand horizontally; let height be its natural “preferred” size
        quiz_frame.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed
        )

        # 4) Now install the layout
        quiz_layout = QVBoxLayout(quiz_frame)
        quiz_layout.setContentsMargins(8,8,8,8)
        quiz_layout.setSpacing(6)
        quiz_frame.setMaximumHeight(360)
        
        quiz_frame.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred
        )
        
        # add your widgets
        quiz_layout.addWidget(self.quiz_info, stretch=1)
        quiz_layout.addWidget(self.question_label, stretch=1)
        for rb in self.option_buttons:
            quiz_layout.addWidget(rb, stretch=0)
        # create a horizontal row for the two buttons
        self.btn_row = QHBoxLayout()
        self.btn_row.addWidget(self.back_btn)     # index 0
        self.btn_row.addStretch(1)                # index 1
        self.btn_row.addWidget(self.submit_btn)   # index 2

        # by default, center the submit_btn...
        self.btn_row.setStretch(0, 1)   # left spacer
        self.btn_row.setStretch(1, 0)   # “real” spacer
        self.btn_row.setStretch(2, 1)   # right spacer

        quiz_layout.addLayout(self.btn_row)

        # 5) Insert & center your card in the main UI
        main_layout.addWidget(quiz_frame, alignment=Qt.AlignmentFlag.AlignHCenter)
        
        # Gear
        #gear_layout = QVBoxLayout()
        gear_top_layout = QHBoxLayout()
        gear_top_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gear1_label = QLabel(self)
        self.gear2_label = QLabel(self)
        self.loadGears()

        gear_top_layout.addWidget(self.gear1_label)
        gear_top_layout.addWidget(self.gear2_label)

        main_layout.addLayout(gear_top_layout)
        
        # Progress Bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(40)  # Increased height
        self.progress_bar.setFixedWidth(600)  # Optional: Make it wider
        self.progress_bar.setStyleSheet("""
            QProgressBar { 
                border: 3px solid black; 
                border-radius: 10px; 
                text-align: center; 
                font-size: 18px; 
                height: 40px; 
                background-color: #E0E0E0;
            }
            QProgressBar::chunk { 
                background-color: #32CD32; 
                width: 10px; 
            }
        """)
        main_layout.addWidget(self.progress_bar, alignment=Qt.AlignmentFlag.AlignCenter)
        self.setLayout(main_layout)
        logger.info("quiz_loading_interface: UI initialized")
        
        self.quiz_index = 0
        self.mode = "fact"
        self.update_quiz_ui()

    def update_quiz_ui(self):
        # Prevent UI update if quiz_data is empty
        if not self.quiz_data or self.quiz_index >= len(self.quiz_data):
            self.quiz_info.setText("⚠️ No quiz content available.")
            self.quiz_info.setStyleSheet("color: red; font-weight: bold; background-color: white;")
            self.quiz_info.show()
            self.question_label.hide()
            for rb in self.option_buttons:
                rb.hide()
            self.submit_btn.hide()
            self.back_btn.hide()
            return
            
        """Show/hide widgets and set texts based on self.mode."""
        total = len(self.quiz_data)
        item  = self.quiz_data[self.quiz_index]
        self.current_item = item        # <<— remember this for on_quiz_button
        
        if self.mode == "fact":
            # Show fact + “Next” on submit_btn
            # center the fact text
            self.quiz_info.setStyleSheet("color: black; background-color: white;")
            self.quiz_info.setText(f"Fact {self.quiz_index+1}/{total}\n\n{item['info']}")
            self.quiz_info.show()

            self.question_label.hide()
            for rb in self.option_buttons: rb.hide()

            self.submit_btn.setText("Next")           # now acts as “go to question”
            self.submit_btn.show()
            self.back_btn.hide()
            
            self.btn_row.setStretch(0, 1)   # left spacer
            self.btn_row.setStretch(1, 0)   # middle spacer
            self.btn_row.setStretch(2, 1)   # right spacer

        elif self.mode == "question":
            # **RESET ANY OLD SELECTIONS HERE**  
            self.options_group.setExclusive(False)
            for rb in self.option_buttons:
                rb.setChecked(False)
            self.options_group.setExclusive(True)
            
            # Show question + options + “Submit” on submit_btn
            self.question_label.setText(f"Q{self.quiz_index+1}/{total}: {item['question']}")
            self.question_label.show()
            for idx, rb in enumerate(self.option_buttons):
                prefix = f"{chr(65 + idx)})"  # 'A)', 'B)', 'C)', 'D)'
                rb.setText(f"{prefix} {item['options'][idx]}")
                rb.show()

            self.quiz_info.hide()

            self.submit_btn.setText("Submit Answer")
            self.submit_btn.show()
            self.back_btn.show()
            
            self.btn_row.setStretch(0, 0)   # left spacer
            self.btn_row.setStretch(1, 1)   # middle spacer
            self.btn_row.setStretch(2, 0)   # right spacer

        elif self.mode == "result":
            # Show feedback in quiz_info + either “Try again” or “Next fact”
            correct = (self.options_group.checkedId() == item['answer'])
            if correct:
                self.quiz_info.setText("✅ Correct!")
                self.quiz_info.setStyleSheet("""
                    background-color: rgba(212, 237, 218, 200);
                    border: 2px solid #28a745;
                    border-radius: 8px;
                    color: #155724;
                    padding: 12px;
                    font-weight: bold;
                """)
                self.submit_btn.setText("Next Fact")
            else:
                self.quiz_info.setText("❌ Wrong—please read the fact again.")
                self.quiz_info.setStyleSheet("""
                    background-color: rgba(248, 215, 218, 200);
                    border: 2px solid #dc3545;
                    border-radius: 8px;
                    color: #721c24;
                    padding: 12px;
                    font-weight: bold;
                """)
                self.submit_btn.setText("Retry Question")

            self.quiz_info.show()
            self.question_label.hide()
            for rb in self.option_buttons: rb.hide()
            self.submit_btn.show()
            self.back_btn.hide()
            
            self.btn_row.setStretch(0, 1)
            self.btn_row.setStretch(1, 0)
            self.btn_row.setStretch(2, 1)
    
    def on_quiz_button(self):
        if self.quiz_index >= len(self.quiz_data):
            QMessageBox.information(self, "Quiz Complete", "You have completed the quiz. Well done!")
            self.submit_btn.setEnabled(False)
            self.back_btn.setEnabled(False)
            return
        elif self.mode == "fact":
            # move to question
            self.mode = "question"
        elif self.mode == "question":
            # grade answer → result
            if self.options_group.checkedId() == -1:
                QMessageBox.warning(self, "No Selection", "Please select an option before submitting.")
                return
            self.mode = "result"
        elif self.mode == "result":
            correct = (self.options_group.checkedId() == self.current_item['answer'])
            if correct:
                # advance to next fact
                self.quiz_index += 1
                if self.quiz_index >= len(self.quiz_data):
                    return  # or loop, or hide quiz entirely...
                self.mode = "fact"
            else:
                # retry question (do not increment index)
                self.mode = "question"

        # finally:
        self.update_quiz_ui()
        
    def on_back_button(self):
        # When in question state, Back should return to the fact panel
        self.mode = "fact"
        self.update_quiz_ui()
        
    def disable_quiz_controls(self):
        # disable submit/back buttons
        self.submit_btn.setEnabled(False)
        self.back_btn.setEnabled(False)
        # disable every radio option
        for rb in self.option_buttons:
            rb.setEnabled(False)


    def loadLogo(self):
        if os.path.exists(self.logo_path):
            pixmap = QPixmap(self.logo_path).scaled(223, 242, Qt.AspectRatioMode.KeepAspectRatio)
            self.logo_label.setPixmap(pixmap)
            logger.info("quiz_loading_interface: Logo loaded successfully")
        else:
            logger.error("quiz_loading_interface: Logo file not found: %s", self.logo_path)

    def loadGears(self):
        if os.path.exists(self.gear_path):
            self.gear_pixmaps = {
                1: QPixmap(self.gear_path).scaled(50, 50, Qt.AspectRatioMode.KeepAspectRatio),
                2: QPixmap(self.gear_path).scaled(80, 80, Qt.AspectRatioMode.KeepAspectRatio)
            }
            self.gear1_label.setPixmap(self.gear_pixmaps[1])
            self.gear2_label.setPixmap(self.gear_pixmaps[2])
            

    def startGearAnimation(self):
        """Start the gear animation only if there is no error."""
        self.gear_angles = {1: 0, 2: 0, 3: 0}
        self.timer = QTimer()
        self.timer.timeout.connect(self.updateGears)
        self.timer.start(100)  # Start the timer to update gears every 100 ms
        logger.info("quiz_loading_interface: Gear animation started")
        
    def updateGears(self):
        for i in range(1, 3):
            self.gear_angles[i] = (self.gear_angles[i] + 10) % 360
            logger.debug("quiz_loading_interface: Gear %s angle updated to %s", i, self.gear_angles[i])
            
            # Get original gear pixmap and size
            original_pixmap = self.gear_pixmaps[i]
            size = original_pixmap.size()
            cx, cy = size.width() // 2, size.height() // 2

            # Apply rotation transformation
            transform = QTransform().translate(cx, cy).rotate(self.gear_angles[i]).translate(-cx, -cy)
            rotated_pixmap = original_pixmap.transformed(transform, Qt.TransformationMode.SmoothTransformation)

            # Create a blank pixmap with a fixed size
            fixed_pixmap = QPixmap(size)
            fixed_pixmap.fill(Qt.GlobalColor.transparent)

            # Use QPainter within the 'with' statement to ensure it ends properly
            with QPainter(fixed_pixmap) as painter:
                painter.drawPixmap((size.width() - rotated_pixmap.width()) // 2, 
                                   (size.height() - rotated_pixmap.height()) // 2, 
                                   rotated_pixmap)
                                   
            getattr(self, f'gear{i}_label').setFixedSize(size)  
            getattr(self, f'gear{i}_label').setPixmap(fixed_pixmap)
            
    def show_error_dialog(self, error_message):
        # Stop the analyzing animation immediately when an error occurs
        self.analysis_worker.stop_timer_signal.emit()  # Stop the timer

        # Update the progress bar immediately before showing the dialog
        self.progress_bar.setValue(100)  # Set the progress bar value to 100
        self.progress_bar.setFormat("Error Encountered !!!")  # Set the format to "Error"
        
        # Show the error dialog
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("Error")
        msg.setText("An error occurred while checking the analysis status.")
        msg.setInformativeText(error_message)
        msg.addButton(QMessageBox.StandardButton.Ok)
        
        msg.exec()  # Show the dialog
        logger.error("quiz_loading_interface: Error dialog shown: %s", error_message)
        
        # Launch the new GUI (upload_file_interface.py)
        python = sys.executable
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upload_file_interface.py")

        # Launch upload_file_interface.py using subprocess
        subprocess.Popen([python, script_path])  # Launch upload_file_interface.py
        
        sys.exit(0)  # Exit the application and terminate upload_file_interface.py
        QApplication.quit()
        self.close()  # Close the current window (quiz_loading_interface.py)

        
    def start_analysis(self):
        self.dot_count = 0  # Tracks the dots in "Analyzing..."
        
        # Timer for "Analyzing..." animation
        self.dot_timer = QTimer()
        self.dot_timer.timeout.connect(self.update_analyzing_text)
        self.dot_timer.start(500)  # Updates every 500ms
        
        # Start the background analysis thread
        self.analysis_worker = AnalysisWorker(self.task_id, self.file_path, self)
        self.analysis_worker.progress_updated.connect(self.update_progress)
        self.analysis_worker.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_worker.stop_timer_signal.connect(self.stop_timer)  # Connect stop_timer_signal to stop_timer method
        self.analysis_worker.start()
        logger.info("quiz_loading_interface: Analysis started")
        
    def stop_timer(self):
        """Stop the timer (used when an error occurs)."""
        if hasattr(self, 'dot_timer'):
            self.dot_timer.stop()
            
        if hasattr(self, 'timer'):
            self.timer.stop()
    
    def update_analyzing_text(self):
        self.dot_count = (self.dot_count + 1) % 4  # Loops through 0, 1, 2, 3
        dots = "." * self.dot_count  # Creates "Analyzing.", "Analyzing..", "Analyzing..."

        # Increment progress value (ensure it doesn't exceed 100)
        new_value = min(self.progress_bar.value() + 1, 99)  # Prevent going beyond 100
        self.progress_bar.setValue(new_value)  # ✅ Update progress bar value

        # Update progress bar format (text inside the bar) {new_value}%
        self.progress_bar.setFormat(f"Loading{dots} ")  # ✅ Update displayed text
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)  # Updates the progress bar

    def on_analysis_complete(self, csv_file_path):
        self.dot_timer.stop()  # Stops the animation timer
        self.process_analysis(csv_file_path)
        logger.info("quiz_loading_interface: Analysis complete; processing completed file: %s", csv_file_path)

    def process_analysis(self, csv_file_path):
        try:
            testing_columns= ["proc_pid", "file", "urls", "type", "name", "ext_urls", "path", "program", "info", "positives",
                    "families", "description", "sign_name", "sign_stacktrace", "arguments", "api", "category",
                    "imported_dll_count", "dll", "pe_res_name", "filetype", "pe_sec_name", "entropy", "hosts", "requests",
                    "mitm", "domains", "dns_servers", "tcp", "udp", "dead_hosts", "proc", "beh_command_line",
                    "process_path", "tree_command_line", "children", "tree_process_name", "command_line", "regkey_read",
                    "directory_enumerated", "regkey_opened", "file_created", "wmi_query", "dll_loaded", "regkey_written",
                    "file_read", "apistats", "errors", "action", "log"]
            
            # ✅ Load the trained model
            try:
                rf_model = joblib.load("/home/kali/Desktop/FYPGUI/rf_model/rf_model.sav")
            except Exception as e:
                logger.error("Error loading model file: %s", e)
                self.progress_bar.setFormat("Error: Failed to load model.")
                return
            
            try:
                label_encoder = joblib.load("/home/kali/Desktop/FYPGUI/rf_model/rf_label_encoder.sav")
            except Exception as e:
                logger.error("Error loading label encoder: %s", e)
                self.progress_bar.setFormat("Error: Failed to load label encoder.")
                return
                
            # Load CSV
            try:
                df = pd.read_csv(csv_file_path)
                missing_cols = [col for col in testing_columns if col not in df.columns]
                if missing_cols:
                    logger.error("Missing columns: %s", missing_cols)
                    self.progress_bar.setFormat("Error: Incomplete features.")
                    return
                df = df[testing_columns]
            except Exception as e:
                logger.error("Error loading or processing CSV: %s", e)
                self.progress_bar.setFormat("Error: Invalid CSV file.")
                return

            # Predict
            try:
                new_prediction = rf_model.predict(df)
                predicted_class = label_encoder.inverse_transform(new_prediction)
                print(predicted_class[0])
                self.progress_bar.setFormat("Analysis Complete!")
                QTimer.singleShot(800, lambda:self.switchToResult(predicted_class[0], self.file_path))
                # ── insert history logging here ──
                record_history(self.file_path, predicted_class[0])
            except Exception as e:
                logger.exception("Error during prediction:")
                self.progress_bar.setFormat("Error: Prediction failed.")

        except Exception as e:
            print(f"Error: {str(e)}")
            self.progress_bar.setFormat(f"Error: {str(e)}")  # Show error if any

    def switchToResult(self, predicted_class, file_path):
        python = sys.executable
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result_interface.py")

        print(f"P {predicted_class}")

        # Launch result_interface.py with task_id and file_path as an argument
        subprocess.Popen([python, script_path, predicted_class, file_path])

        # Close the current GUI
        self.close()
        QApplication.quit()
        sys.exit(0)

    def setupCodeWatcher(self):
        script_path = os.path.abspath(__file__)
        if os.path.exists(script_path):
            self.code_watcher.addPath(script_path)
            self.code_watcher.fileChanged.connect(self.restartApp)
            logger.info("quiz_loading_interface: Code watcher set on %s", script_path)

    def restartApp(self):
        logger.info("quiz_loading_interface: Detected changes in quiz_loading_interface.py. Restarting application...")
        QTimer.singleShot(1000, self.relaunch)

    def relaunch(self):
        logger.info("quiz_loading_interface: Relaunching quiz_loading_interface.py...")
        python = sys.executable
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        print(f"Restarting from: {script_path}")
        subprocess.Popen([python, script_path], cwd=script_dir)
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: quiz_loading_interface.py <task_id> <file_path>")
        sys.exit(1)

    task_id = sys.argv[1]
    file_path = sys.argv[2]

    print(f"Received Task ID: {task_id}, File Path: {file_path}")

    # Initialize GUI with parameters
    app = QApplication(sys.argv)
    window = RansomSpyGUI(task_id, file_path)
    window.show()
    sys.exit(app.exec())
