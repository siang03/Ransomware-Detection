import sys
import os
import subprocess
import logging
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout, 
    QSpacerItem, QSizePolicy, QFrame, QMessageBox
)
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtCore import Qt, QFileSystemWatcher, QTimer
from file_behavior_analysis import submit_to_cuckoo

# Import and configure logging
import log_config

logger = logging.getLogger(__name__)


class RansomSpyGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.logo_path = "/home/kali/Desktop/FYPGUI/assets/gui/image_1.png"
        self.fingerprint_path = "/home/kali/Desktop/FYPGUI/assets/gui/image_2.png"
        self.watched_file = None
        self.file_watcher = QFileSystemWatcher()
        self.code_watcher = QFileSystemWatcher()

        self.initUI()
        self.setupCodeWatcher()  # Monitor GUI file for changes

    def initUI(self):
        self.setWindowTitle("RansomSpy")
        self.setStyleSheet("background-color: #57e1f7;")
        self.setGeometry(350, 40, 1080, 832)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)  # No space between subtitle and line

        third_layout = QVBoxLayout()
        third_layout.setContentsMargins(0, 0, 0, 0)
        third_layout.setSpacing(0)

        top_layout = QHBoxLayout()
        top_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Center the entire layout

        # Logo (Make it bigger)
        self.logo_label = QLabel(self)
        self.loadLogo()

        # Add small spacing between logo and label
        spacer = QSpacerItem(10, 10, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        # Title (Ensure alignment)
        self.title = QLabel("RansomSpy", self)
        self.title.setFont(QFont("Inter", 60, QFont.Weight.ExtraBold))
        self.title.setStyleSheet("color: black;")

        # Add widgets to horizontal layout
        top_layout.addWidget(self.logo_label, alignment=Qt.AlignmentFlag.AlignVCenter)  # Align logo at center
        top_layout.addItem(spacer)  # Add small space
        top_layout.addWidget(self.title, alignment=Qt.AlignmentFlag.AlignVCenter)  # Align text at center
        main_layout.addLayout(top_layout)

        # Second Layout
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

        # Third Layout
        third_layout = QVBoxLayout()
        self.fingerprint_label = QLabel(self)
        self.loadFingerprint()
        self.fingerprint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        third_layout.addWidget(self.fingerprint_label)

        third_layout.addSpacing(20)  # Add space between fingerprint and button
        
        self.upload_button = QPushButton("Choose file", self)
        self.upload_button.setStyleSheet("""
            QPushButton {
                background-color: black;
                color: white;
                padding: 12px;
                border-radius: 10px;
                font-size: 24px;
            }
            QPushButton:hover {
                background-color: #333333;  /* Darker shade on hover */
                color: #57e1f7;  /* Change text color on hover */
            }
                                         
        """)
        self.upload_button.setFixedSize(187, 65)  # Set width and height
        self.upload_button.clicked.connect(self.openFileDialog)
        third_layout.addWidget(self.upload_button, alignment=Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        main_layout.addLayout(third_layout)
        
        
        self.history_btn = QPushButton("View History", self)
        self.history_btn.setStyleSheet("QPushButton{ color: black; }")
        self.history_btn.setFixedSize(150, 40)
        self.history_btn.clicked.connect(self.open_history)
        main_layout.addWidget(self.history_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        

        self.disclaimer = QLabel(
            "Maximum file upload size is 125 MB.",
            self
        )
        self.disclaimer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.disclaimer.setFixedWidth(562)
        self.disclaimer.setWordWrap(True)
        self.disclaimer.setStyleSheet("color: black; font-size: 20px;")
        main_layout.addWidget(self.disclaimer, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(main_layout)
    
    def open_history(self):
        python = sys.executable
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history_interface.py")
        subprocess.Popen([python, script])
        self.close()
    
    def loadLogo(self):
        if os.path.exists(self.logo_path):
            pixmap = QPixmap(self.logo_path).scaled(223, 242, Qt.AspectRatioMode.KeepAspectRatio)
            self.logo_label.setPixmap(pixmap)
            logger.info("Logo loaded from %s", self.logo_path)
        else:
            logger.error("Logo file not found: %s", self.logo_path)

    def loadFingerprint(self):
        if os.path.exists(self.fingerprint_path):
            pixmap = QPixmap(self.fingerprint_path).scaled(449, 299, Qt.AspectRatioMode.KeepAspectRatio)
            self.fingerprint_label.setPixmap(pixmap)
            logger.info("Fingerprint image loaded from %s", self.fingerprint_path)
        else:
            logger.error("Fingerprint file not found: %s", self.fingerprint_path)
            
    def is_file_size_valid(self, file_path):
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        return size_mb <= 125
        
    def openFileDialog(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_path, _ = file_dialog.getOpenFileName(self, "Select File")
        
        if file_path:
            if not self.is_file_size_valid(file_path):
                msg_box = QMessageBox(self)
                msg_box.setIcon(QMessageBox.Icon.Warning)
                msg_box.setWindowTitle("File Too Large")
                msg_box.setText(f"The selected file exceeds the 125 MB limit.\n\nPlease choose a smaller file.")
                self.applyMessageBoxStyle(msg_box)
                msg_box.exec()
                return  # Stop the process
                
            logger.info("Selected file: %s", file_path)
            self.confirmAnalysis(file_path)
            
            if self.watched_file:
                self.file_watcher.removePath(self.watched_file)
            
            self.watched_file = file_path
            self.file_watcher.addPath(self.watched_file)
            self.file_watcher.fileChanged.connect(self.fileUpdated)

    def applyMessageBoxStyle(self, msg_box):
        """Apply a full white background style to QMessageBox."""
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: white;  /* Full white background */
                color: black;
                font-size: 14px;
                border: none;  /* Remove any border */
            }
            QLabel {
                color: black;
                background: white;  /* Ensure white background for text */
            }
            QPushButton {
                background-color: #0078D7;  /* Default Windows blue */
                color: white;
                border-radius: 4px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #005A9E;
            }
        """)


    def confirmAnalysis(self, file_path):
        """Prompt user before submitting file for analysis."""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Question)
        msg_box.setWindowTitle("Confirm Analysis")
        msg_box.setText(f"Selected file:\n{file_path}\n\nDo you want to analyze this file?")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        self.applyMessageBoxStyle(msg_box)  # Apply the style

        response = msg_box.exec()
        
        if response == QMessageBox.StandardButton.Yes:
            logger.info("User confirmed analysis for file: %s", file_path)
            self.analyzeFile(file_path)
        else:
            logger.info("User cancelled analysis for file: %s", file_path)

    def analyzeFile(self, file_path):
        """Submit the file to Cuckoo Sandbox for analysis."""
        logger.info("Submitting %s to Cuckoo...", file_path)
        task_id = submit_to_cuckoo(file_path)
        msg_box = QMessageBox(self)

        if task_id:
            msg_box.setIcon(QMessageBox.Icon.Information)
            msg_box.setWindowTitle("Submission Successful")
            msg_box.setText(f"File submitted successfully. Task ID: {task_id}")
            logger.info("File submitted with Task ID: %s", task_id)
        else:
            msg_box.setIcon(QMessageBox.Icon.Warning)
            msg_box.setWindowTitle("Submission Failed")
            msg_box.setText("File submission failed.")
            logger.error("File submission failed for: %s", file_path)

        self.applyMessageBoxStyle(msg_box)  # Apply the style
        msg_box.exec()

        if task_id:
            self.switchToQuiz(task_id, file_path)
    
    def switchToQuiz(self, task_id, file_path):
        """Close current GUI and open quiz_loading_interface.py with task_id."""
        python = sys.executable
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quiz_loading_interface.py")
        logger.info("Switching to %s with Task ID: %s and File Path: %s", script_path, task_id, file_path)
        # Launch quiz_loading_interface.py with task_id and file_path as an argument
        subprocess.Popen([python, script_path, str(task_id), file_path])

        # Close the current GUI
        self.close()
        sys.exit(0)

    def fileUpdated(self, path):
        logger.info("File %s was updated! Performing re-analysis...", path)

    def setupCodeWatcher(self):
        """Monitors upload_file_interface.py for changes and restarts the application if modified."""
        script_path = os.path.abspath(__file__)  # Get current script's full path

        if os.path.exists(script_path):
            self.code_watcher.addPath(script_path)
            self.code_watcher.fileChanged.connect(self.restartApp)
            logger.info("Code watcher set up for %s", script_path)

    def restartApp(self):
        """Restarts the application when upload_file_interface.py is modified."""
        logger.info("Detected changes in upload_file_interface.py. Restarting the application...")
        QTimer.singleShot(1000, self.relaunch)  # Delay to avoid multiple triggers

    def relaunch(self):
        logger.info("Relaunching application...")
        """Closes the current instance and launches a new one."""
        python = sys.executable
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)  # Get script directory
        print(f"Restarting from: {script_path}")

        subprocess.Popen([python, script_path], cwd=script_dir)  # Restart in correct directory
        sys.exit(0)  # Close the current instance

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RansomSpyGUI()
    window.show()
    sys.exit(app.exec())
