##This code is ran on foxit for trainig an Isolated forest mode.
#The code runs on the machine and extracts two PKL files.
#Encoder.PKL -> Contains the label encodings observed during training
#Model.PKL -> Contains the model training.

import ijson
import json
import pandas as pd
import numpy as np
#import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib  # Library to save and load models
import os

#MODEL_FILE = "isolation_forest_model.pkl"  # File to save the trained model

# === CONFIGURATION ===
LOG_FILES = ["JSON_FILES_WITH_SYSMON_DATA"] #ONE or MORE files with sysmon log data
SAVE_DIR = "PKL_FILES/" #Where the PKL FILES Should be saved
BATCH_SIZE = 100000  # Number of logs to process at a time
CONTAMINATION = 0.001  # Anomaly contamination level
MODEL_FILE =  os.path.join(SAVE_DIR,"MODEL_FOX_SOLUTION_Without_Images.pkl")  # Filename of the saved model file. 


# LOLBIN list for detection
LOLBIN_PROCESSES = {"rundll32.exe", "mshta.exe", "certutil.exe", "powershell.exe", "cmd.exe"}


#FEATURE EXTRACTION
important_fields = {"@timestamp", "Image", "ParentImage", "ParentProcessGuid","ProcessGuid", "Hostname"} #Important fields to be extracted. 
all_data = []  # Store all logs for full dataset processing
features = ["NormalizedFreq","PairFrequency","ProcessCount","ParentProcessCount","IsLOLBAS"] #The features from engineering.

"""
Filter_log - takes a log input and only extracts the fields which are in the variable important_fields.

- Used to save space when importing large amount of logs.
"""
def filter_log(log):
    """Extract only relevant fields."""
    return {k: v for k, v in log.items() if k in important_fields}


"""
Function to load SYSMON Logs
"""
def load_sysmon_logs(LOG_FILES, batch_size=10000):
    """Stream-read Sysmon JSON logs in batches and store them in a dataframe."""
    global all_data


    for file_path in LOG_FILES:
        log_count = 0
        with open(file_path, "r", encoding="utf-8") as f:
            parser = ijson.items(f, "results.item")
            batch = []
            for i, log in enumerate(parser):
                if i < 50:  # Print first 5 logs to check structure
                    print("Sample Log:", log)
                filtered_log = filter_log(log)
                if filtered_log:
                    batch.append(filtered_log)

                if len(batch) >= batch_size:
                    all_data.extend(batch)
                    batch = []
                    log_count += batch_size
                    
                    if log_count % 5000000 == 0:
                        print(f"Loaded {log_count} logs...")

                

                #if log_count> 1000000: 
                    #print("Breaking")
                    #break
            if batch:
                all_data.extend(batch)
        
    print(f"Total logs loaded: {len(all_data)}") ##Print amount of training data.

"""
Train Isolation Forest on all logs and detect anomalies.

Output is a .PKL file with the model. That is used in classify_predict.py and classify_decision_boundary.py
@Author Odin
"""


def fit_model():
    print("Training all data is:", len(all_data))
    df = pd.DataFrame(all_data)
    
    df["LogIndex"] = df.index

    df = df[df["ParentProcessGuid"] != "{00000000-0000-0000-0000-000000000000}"]  ##Remove logs without a parent before training. 

    """
    FEATURE ENGINEERING
    -PairFrequency  - The frequency of a parent - child pair
    -NormalizedFreq - Normalized Frequency of pair
    -ProcessCount   - How many times the process created has spawned.
    -ParentProcessCount - How many times the parent process has been spawned.
    -IsLOLBAS           - If the image is a LOLBIN. 
    """
    # Pair and Normalized frequency.
    df["ParentChildPair"] = df["ParentImage"] + " -> " + df["Image"]
    pair_counts = df["ParentChildPair"].value_counts()
    df["PairFrequency"] = df["ParentChildPair"].map(pair_counts)
    df["NormalizedFreq"] = 1 / (df["PairFrequency"] + 1)  # Avoid division by zero

    # RARE PROCESS
    df["ProcessCount"] = df["Image"].map(df["Image"].value_counts())
    df["ParentProcessCount"] = df["ParentImage"].map(df["ParentImage"].value_counts())

     # Detect LOLBIN usage
    df["IsLOLBAS"] = df["Image"].apply(lambda x: 1 if x.lower() in LOLBIN_PROCESSES else 0)


    # Train Isolation Forest
    model = IsolationForest(n_estimators=100, contamination=CONTAMINATION, random_state=42)
    model.fit(df[features])

    os.makedirs(SAVE_DIR, exist_ok=True)
    
    
    try:
        joblib.dump(model, MODEL_FILE)
        print(f"Model saved successfully: {MODEL_FILE}")
    except Exception as e:
        print(f"Failed to save model: {e}")

    return model

load_sysmon_logs(LOG_FILES)
fit_model()
