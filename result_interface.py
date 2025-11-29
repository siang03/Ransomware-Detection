import hashlib
import ssdeep
import tlsh
import pefile
import lief
import magic
import sys
import json
import os
import subprocess
import logging

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, 
    QSpacerItem, QSizePolicy, QFrame, QPushButton, QGraphicsDropShadowEffect
)
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtCore import Qt, QFileSystemWatcher, QTimer

# Import common logging configuration
import log_config

logger = logging.getLogger(__name__)

class RansomSpyGUI(QWidget):

    def __init__(self, predicted_class, file_path):
        super().__init__()
        self.logo_path = "/home/kali/Desktop/FYPGUI/assets/gui/image_1.png"
        self.virus_icon_path = "/home/kali/Desktop/FYPGUI/assets/gui/virus.png"
        self.legit_icon_path = "/home/kali/Desktop/FYPGUI/assets/gui/smile.png"
        self.watched_file = None
        self.file_watcher = QFileSystemWatcher()
        self.code_watcher = QFileSystemWatcher()
        self.file_path = file_path

        self.prediction_result = predicted_class  # Change to "benign" to test
        
        self.initUI()
        self.setupCodeWatcher()

        # Ensure the window is visible and focused
        self.setWindowState(Qt.WindowState.WindowActive)  # Ensure it's active
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)  # Force it to appear on top
        self.show()  # Show the window
        logger.info("result_interface: Initialized with prediction: %s, File: %s", predicted_class, file_path)

    def initUI(self):
        self.setWindowTitle("RansomSpy")
        self.setStyleSheet("background-color: #57e1f7;")
        self.setGeometry(350, 40, 1200, 1100)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

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

        # Virus Icon
        self.virus_label = QLabel(self)
        self.loadVirusIcon()
        main_layout.addWidget(self.virus_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Legitimare Icon
        self.legit_label = QLabel(self)
        self.loadLegitIcon()
        main_layout.addWidget(self.legit_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Warning Text
        self.warning_label = QLabel("THIS FILE IS VERY LIKELY A RANSOMWARE!!", self)
        self.warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.warning_label.setFont(QFont("Inter", 24, QFont.Weight.Bold))
        self.warning_label.setStyleSheet("color: black;")
        main_layout.addWidget(self.warning_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Legit Text
        self.safe_label = QLabel("THIS FILE IS VERY LIKELY SAFE!!", self)
        self.safe_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.safe_label.setFont(QFont("Inter", 24, QFont.Weight.Bold))
        self.safe_label.setStyleSheet("color: black;")
        main_layout.addWidget(self.safe_label, alignment=Qt.AlignmentFlag.AlignCenter)
           
        # File Info
        self.file_info_label = QLabel(self.format_file_info(), self)
        self.file_info_label.setFont(QFont("Inter", 14))
        self.file_info_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.file_info_label.setStyleSheet("color: black; padding: 10px; border-radius: 5px;")
        main_layout.addWidget(self.file_info_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Home Button  
        self.home_button = QPushButton("Exit", self)
        self.home_button.setStyleSheet(
            "background-color: lightgray; color: black; font-size: 18px; font-weight: bold;"
        )
        self.home_button.setFixedSize(250, 50)
        self.home_button.clicked.connect(self.switchToUploadFile)  # Connect to function
        main_layout.addWidget(self.home_button, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.updateUIBasedOnPrediction()
        self.setLayout(main_layout)
        logger.info("result_interface: UI initialized")
    
    def open_history(self):
        python = sys.executable
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history_interface.py")
        subprocess.Popen([python, script, self.file_path])
        self.close()

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
            pixmap = QPixmap(self.logo_path).scaled(223, 242, Qt.AspectRatioMode.KeepAspectRatio)
            self.logo_label.setPixmap(pixmap)
            logger.info("result_interface: Logo loaded from %s", self.logo_path)
        else:
            logger.error("result_interface: Logo file not found: %s", self.logo_path)

    def loadVirusIcon(self):
        if os.path.exists(self.virus_icon_path):
            pixmap = QPixmap(self.virus_icon_path).scaled(300, 150, Qt.AspectRatioMode.KeepAspectRatio)
            self.virus_label.setPixmap(pixmap)

    def loadLegitIcon(self):
        if os.path.exists(self.legit_icon_path):
            pixmap = QPixmap(self.legit_icon_path).scaled(389, 239, Qt.AspectRatioMode.KeepAspectRatio)
            self.legit_label.setPixmap(pixmap)

    def updateUIBasedOnPrediction(self):
        """
        Show relevant UI elements based on the prediction result.
        """
        if self.prediction_result == "R":
            self.virus_label.show()
            self.warning_label.show()
            self.legit_label.hide()
            self.safe_label.hide()
            logger.info("result_interface: Prediction indicates ransomware")
        else:
            self.virus_label.hide()
            self.warning_label.hide()
            self.legit_label.show()
            self.safe_label.show()
            logger.info("result_interface: Prediction indicates safe file")
            
    def compute_hashes(self, file_path):
        """Compute MD5, SHA-1, SHA-256 hashes."""
        hashes = {'MD5': hashlib.md5(), 'SHA-1': hashlib.sha1(), 'SHA-256': hashlib.sha256()}
        
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                for h in hashes.values():
                    h.update(chunk)
    
        return {name: h.hexdigest() for name, h in hashes.items()}

    def get_ssdeep(self, file_path):
        """Compute SSDEEP fuzzy hash."""
        try:
            return ssdeep.hash_from_file(file_path)
        except:
            return "N/A"

    def get_tlsh(self, file_path):
        """Compute TLSH hash."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return tlsh.hash(data)
        except:
            return "N/A"

    def get_file_type(self, file_path):
        """Identify file type using `magic` and provide both category and full description."""
        try:
            raw_type = magic.from_file(file_path)
            category = "Unknown"
            if "PE32 executable" in raw_type:
                category = "Win32 EXE"
            elif "PE64 executable" in raw_type:
                category = "Win64 EXE"
            elif "ELF" in raw_type:
                category = "Linux ELF"
            elif "Mach-O" in raw_type:
                category = "Mac Mach-O"
            
            return category, raw_type  # Return both simplified type and full magic output
        except:
            return "Unknown", "N/A"

    def get_pe_info(self, file_path):
        """Extract PE header details including Authentihash."""
        try:
            pe = lief.PE.parse(file_path)
            if pe:
                return pe.authentihash(lief.PE.ALGORITHMS.SHA_256).hex()  # You can use SHA1 or SHA256 as well
            else:
                return "N/A"
        except Exception as e:
            print(f"Error calculating Authentihash: {e}")
            return "N/A"

    def get_file_size(self, file_path):
        """Get file size in MB and bytes."""
        size_bytes = os.path.getsize(file_path)
        size_mb = size_bytes / (1024 * 1024)
        return f"{size_mb:.2f} MB ({size_bytes} bytes)"
    
    def format_file_info(self):
        hashes = self.compute_hashes(self.file_path)
        authentihash = self.get_pe_info(self.file_path)
        category, magic_output = self.get_file_type(self.file_path)
        
        return (f"<table style='width: 100%; border: 1px solid black; border-collapse: collapse;'>"
            f"<tr><td colspan='2' style='border: 1px solid black; text-align: left; font-weight: bold; font-size: 20px; padding: 5px;'>Basic Properties:</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>MD5</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{hashes['MD5']}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>SHA-1</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{hashes['SHA-1']}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>SHA-256</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{hashes['SHA-256']}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>Authentihash</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{authentihash}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>SSDEEP</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{self.get_ssdeep(self.file_path)}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>TLSH</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{self.get_tlsh(self.file_path)}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>File Name</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{os.path.basename(self.file_path)}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>File Type</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{magic_output}</td></tr>"
            f"<tr><td style='text-align: left; border: 1px solid black; padding: 5px;'><b>Size</b></td><td style='text-align: left; border: 1px solid black; padding: 5px;'>{self.get_file_size(self.file_path)}</td></tr>"
            f"</table>")
                
    def setupCodeWatcher(self):
        script_path = os.path.abspath(__file__)
        if os.path.exists(script_path):
            self.code_watcher.addPath(script_path)
            self.code_watcher.fileChanged.connect(self.restartApp)
            logger.info("result_interface: Code watcher set on %s", script_path)

    def restartApp(self):
        logger.info("result_interface: Detected changes in result_interface.py. Restarting application...")
        QTimer.singleShot(1000, self.relaunch)

    def relaunch(self):
        logger.info("result_interface: Relaunching result_interface.py...")
        python = sys.executable
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        print(f"Restarting from: {script_path}")
        subprocess.Popen([python, script_path], cwd=script_dir)
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print ("unknown")
        sys.exit(1)

    predicted_class = sys.argv[1]
    file_path = sys.argv[2]
    print(f"Received Prediction: {predicted_class}; File path: {file_path}")

    app = QApplication(sys.argv)
    window = RansomSpyGUI(predicted_class, file_path)
    window.show()
    sys.exit(app.exec())
