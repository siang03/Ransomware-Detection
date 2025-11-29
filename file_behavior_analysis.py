import os
import time
import requests
import logging
import log_config 
from filter import process

logger = logging.getLogger(__name__)

# Cuckoo API URL (Replace with your actual Kali VM IP)
CUCKOO_API = "replace_with_your_own_api"
BEARER_TOKEN = "replace_with_your_own_token"  # Your token
REPORT_FOLDER = "/home/kali/Desktop/FYPGUI/JSON"  # Folder to save JSON reports
os.makedirs(REPORT_FOLDER, exist_ok=True)   # ← make sure this directory exists

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}"
}

def submit_to_cuckoo(file_path):
    logger.info("Trying to open file: %s", file_path)
    
    if not os.path.exists(file_path):
        logger.error("File not found: %s", file_path)
        return None  # Exit early if the file is missing

    time.sleep(1)  # Ensure file stability

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(f"{CUCKOO_API}/tasks/create/file", headers=headers, files=files)
        if response.status_code == 200:
            task_id = response.json().get("task_id")
            logger.info("File submitted successfully. Task ID: %s", task_id)
            return task_id
        else:
            logger.error("Failed to submit file. Status code: %s", response.status_code)
            return None
    except Exception as e:
        logger.exception("Error while submitting file: %s", e)
        return None

def check_task_status(task_id):
    while True:
        response = requests.get(f"{CUCKOO_API}/tasks/view/{task_id}", headers=headers)
        if response.status_code == 200:
            status = response.json().get("task", {}).get("status")
            if status == "reported":
                logger.info("Analysis complete for Task ID: %s", task_id)
                return True
        logger.info("Waiting for analysis... Task ID: %s", task_id)
        time.sleep(10)

def fetch_cuckoo_report(task_id, file_path):
    if check_task_status(task_id):
        response = requests.get(f"{CUCKOO_API}/tasks/report/{task_id}", headers=headers)
        if response.status_code == 200:
            file_name = os.path.basename(file_path)
            base_name, _ = os.path.splitext(file_name)  # Remove the extension
            report_path = os.path.join(REPORT_FOLDER, f"{base_name}.json")
            try:
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
                logger.info("Report saved to: %s", report_path)
            except Exception as e:
                logger.exception("Failed to save report file: %s", e)
                return None

            # Call process and return its result (CSV file path)
            csv_path = process(report_path)
            return csv_path  # Ensure this returns the correct CSV file path
        else:
            logger.error("Failed to fetch report. Status code: %s", response.status_code)
            return None

if __name__ == "__main__":
    file_path = input("Enter the file path to submit for analysis: ").strip()
    
    if os.path.exists(file_path):
        task_id = submit_to_cuckoo(file_path)
        if task_id:
            fetch_cuckoo_report(task_id, file_path)
    else:
        logger.error("The specified file does not exist: %s", file_path)

