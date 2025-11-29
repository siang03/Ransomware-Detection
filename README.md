# 🛡️ Behavior-Based Ransomware Detection System

A GUI-based ransomware detection system that analyzes uploaded files using behavior analysis and machine learning.  
The system submits files to a sandbox environment, extracts runtime behavior, and classifies the file as **benign** or **ransomware** using a trained ML model.

This project provides a Python-based desktop GUI, allowing users to upload files and trigger analysis seamlessly.  
Machine learning logic and sandbox submission flow are handled internally.

---

## ✨ Features

- Simple GUI built with Python for uploading files  
- Behavior-based analysis (not signature-based)  
- Integration with **Cuckoo Sandbox** via API  
- Automatic file submission for dynamic analysis  
- Machine learning model for ransomware classification  
- Clear result output  
- Lightweight and easy to run locally once dependencies are installed  

---

## ⚠️ Cuckoo Sandbox Setup (Required)

This system **requires Cuckoo Sandbox** for behavior analysis.

Users must:

- Install Cuckoo Sandbox  
- Run the Cuckoo API  
- Ensure the API endpoint is reachable  
- Configure the correct API URL inside the project files  

**Cuckoo Sandbox and its API are not provided in this repository.**  
Users are responsible for setting up their own environment.

---

## 🚀 Running the Application

Launch the GUI using:

```bash
python upload_file_interface.py
```

Once launched:

- Click **Upload File**
- Choose the file you want to analyze
- The system will submit the file to the configured Cuckoo API
- Wait for results
- The machine learning model will output whether the file is **benign** or **ransomware**

---

## 🔍 How It Works

1. User uploads a file through the GUI  
2. File is sent to the **Cuckoo Sandbox API**  
3. Cuckoo analyzes the file inside a virtual machine  
4. A behavioral report is generated  
5. The system extracts and processes relevant behavioral features  
6. ML model predicts **ransomware** or **benign**  

This approach detects ransomware based on **real behavior**, making it effective even against new or obfuscated variants.

---

## 🧠 Machine Learning Model

- Built using Python and **scikit-learn**  
- Trained on behavioral features extracted from Cuckoo reports  
- Performs binary classification  
- Designed for simplicity and fast inference  

---

## 📌 Notes & Limitations

- Requires a working **Cuckoo Sandbox** instance  
- Analysis time depends on VM performance  
- Intended for educational and research purposes  
- Behavior-based detection may vary depending on the stability of the sandbox environment  
- **Mitigation actions are not included** — this system performs detection only  

---

