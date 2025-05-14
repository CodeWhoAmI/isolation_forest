import ijson #Used in batch processing
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt #Plots
from sklearn.ensemble import IsolationForest #IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib  # Library to save and load models
import os
import seaborn as sns ##Import seaborn for figures.

"""
variables used for configuration.
"""
CLASSIFICATION_DATA = "vasketData080424.json" ##Sysmon log file with data.
MALICIOUS_LOGS ="malicious_logs.json" # The malicious dataset.
BATCH_SIZE = 10000  # Number of logs to process at a time - Used for batch processing in reading large log files.
MODEL_FILE = "MODEL_FILE_GENERATED_DURING_TRAINING.pkl"  # File of the trained model


# LOLBIN list for detection scope
LOLBIN_PROCESSES = {"rundll32.exe", "mshta.exe", "certutil.exe", "powershell.exe", "cmd.exe"}


#FEATURE EXTRACTION
important_fields = {"@timestamp", "Image", "ParentImage", "ParentProcessGuid","ProcessGuid", "Hostname"} #Fields to extract from the imported logs.

features = ["NormalizedFreq","PairFrequency","ProcessCount","ParentProcessCount","IsLOLBAS"] #Features that are used during training and classification. Same as Feature engineered below. 


"""
Filter_log - takes a log input and only extracts the fields which are in the variable important_fields.

- Used to save space when importing large amount of logs.
"""
def filter_log(log):
    """Extract only relevant fields."""
    return {k: v for k, v in log.items() if k in important_fields}


"""
Function: Classify_data

Used to classify anomalies in the data. 

Parameter:
Takes the model file as an input parameter.

Uses the decision boundary method to classify anomalies, and results in an output of anomalies.json
(Containing flagged anomalies)

And filtered_anomalies.json (Anomalies after filtering.)

Called from main. 

@Author Odin
"""

def classify_data(model):
    
    """
    Load the classification dataset using batch processing
    """  
    all_data = []
    with open(CLASSIFICATION_DATA, "r", encoding="utf-8") as f:
        parser = ijson.items(f, "results.item")
        batch = []
        for i, log in enumerate(parser): ##Enumerate the dataset and filter logs
            filtered_log = filter_log(log)
            if filtered_log:
                batch.append(filtered_log)
            if len(batch) >= BATCH_SIZE: #Adjust the batch size of logs to read at a time. 
                print(f"Loaded {i} logs...")
                all_data.extend(batch) #Add logs for later processing
                batch = []
        if batch:
            all_data.extend(batch) #Add logs for later processing

    with open(MALICIOUS_LOGS, "r", encoding="utf-8") as file: ##Inject the malicious logs into the dataset. 
        logs = json.load(file)["results"]
        if logs:
            all_data.extend(logs)
            print("Added the malicious logs")
        
    print(f"Total logs loaded: {len(all_data)}") ##How many logs are loaded in total.

    ##Load classification logs
    classification_df = pd.DataFrame(all_data) #Create a dataframe of the logs.

    classification_df["LogIndex"] = classification_df.index #Add the log index.

    classification_df = classification_df[classification_df["ParentProcessGuid"] != "{00000000-0000-0000-0000-000000000000}"] #Remove logs with processParentGuid of 0. - Meaning no parents.


    """
    FEATURE ENGINEERING
    -PairFrequency  - The frequency of a parent - child pair
    -NormalizedFreq - Normalized Frequency of pair
    -ProcessCount   - How many times the process created has spawned.
    -ParentProcessCount - How many times the parent process has been spawned.
    -IsLOLBAS           - If the image is a LOLBIN. 
    """
    # Feature Engineering for Classification Data
    classification_df["ParentChildPair"] = classification_df["ParentImage"] + " -> " + classification_df["Image"]
    pair_counts = classification_df["ParentChildPair"].value_counts()
    classification_df["PairFrequency"] = classification_df["ParentChildPair"].map(pair_counts)
    classification_df["NormalizedFreq"] = 1 / (classification_df["PairFrequency"] + 1)  # Avoid division by zero and not make extreme values. 

    # RARE PROCESS
    classification_df["ProcessCount"] = classification_df["Image"].map(classification_df["Image"].value_counts())
    classification_df["ParentProcessCount"] = classification_df["ParentImage"].map(classification_df["ParentImage"].value_counts())

    # Detect LOLBAS usage
    classification_df["IsLOLBAS"] = classification_df["Image"].apply(lambda x: 1 if x.lower() in LOLBIN_PROCESSES else 0)

    

    """
    Calculate the anomaly score for every log.
    
    """
    ## Calculate the anomaly score for every single log.
    classification_df["AnomalyScore"] = model.decision_function(classification_df[features])


    ################ SCALING ANOMALY SCORE #################

    #Finding the MAX ANOMALY for later scaling
    max_anomaly = classification_df["AnomalyScore"].min() ##Get the most anomalous value
    
    #Getting the scaled anomaly score. Based on the Anomaly Score Table devided by the top anomaly. 
    # This makes the largest anomaly be a -1. 
    classification_df["ScaledAnomalyScore"] = classification_df["AnomalyScore"] / abs(max_anomaly)  # Scale based on max anomaly

    
    """
    Classify anomalies using the decision boundary
    Uses threshold of -0.5 of the scaled anomaly score.
    """
    threshold = -0.5  # Lower values indicate stronger anomalies
    classification_df["IsAnomaly"] = classification_df["ScaledAnomalyScore"].apply(lambda x: -1 if x < threshold else 1)
    
    

    """
    FILTERING
    Filter Idea that removes anomalies with a certain pair frequency to LOLBAS child ratio of parent process execution. 
    Not implemented inline but outputted how many anomalies that this would result in filtered out.
    """

    filter_df=classification_df.copy() #Dataframe that the filtering is applied to , so that I can view the use of it. 
    filter_df["PairFrequencyRatio"] = filter_df["PairFrequency"] / filter_df["ParentProcessCount"]
    #Filter idea 1: 
        #Filter out anomalies that commonly use a specific lolbas in a lot of their executions.
        #The spawned lolbas child needs to be a certain percentage of spawned processes on the system.

    #Set parent count threshhold:
    parent_count_threshold = 20 ## Remove logs over this threshhold in concurrency with the below variable.
    high_ratio_of_lolbas_child = 0.70 ## Remove logs over this threshhold

    #Calculate the Pair Frequency Rate and add to DF
    filter_df["PairFrequencyRatio"] = filter_df["PairFrequency"] / filter_df["ParentProcessCount"]
    

    ##Set condition
    filter_condition = (filter_df["ParentProcessCount"] >= parent_count_threshold) & \
                   (filter_df["PairFrequencyRatio"] >= high_ratio_of_lolbas_child)

    

    # Apply the filter
    filter_df = filter_df.loc[~filter_condition]


    """
    Get all the anomalies classified.
    """
    anomalies = classification_df[classification_df["IsAnomaly"] == -1].copy()
    if not anomalies.empty:
        print("Total amount of anomalies:", len(anomalies)) #Print how many anomalies identified.

        anomalies = anomalies.sort_values(by="AnomalyScore", ascending=True)  # Lower score = more anomalous
        
        anomaly_logs = []

        """Iterate through anomalies and append the features of them to the original logs for later viewing."""
        for idx, row in anomalies.iterrows():
            log_entry = all_data[idx]  # Get original log entry
            log_entry["PairFrequency"] = row["PairFrequency"]  # Append PairFrequency
            log_entry["NormalizedFrequency"] = row["NormalizedFreq"]
            log_entry["AnomalyScore"] = row["AnomalyScore"] #Append the anomaly score.
            log_entry["ScaledAnomalyScore"] = row["ScaledAnomalyScore"]
            log_entry["ProcessCount"] = row["ProcessCount"]
            log_entry["ParentProcessCount"] = row["ParentProcessCount"]
            anomaly_logs.append(log_entry)

        """
        Write anomaly logs to file anomalies.json
        """
        with open("anomalies.json", "w", encoding="utf-8") as f:
            json.dump(anomaly_logs, f, indent=4)

        

        """
        Write the top 10 normal logs to file called Top_Normal_Logs.json
        """
        df_sorted = classification_df.sort_values("AnomalyScore", ascending=False).head(10)  # Top 10 anomalies
        top_normal_logs = [all_data[idx] for idx in df_sorted["LogIndex"]]
        
        with open("Top_Normal_Logs.json", "w", encoding="utf-8") as f:
            json.dump(top_normal_logs, f, indent=4)

        """
        Create a sperate list of the anomalies after filtering. 
        Write these to a file called filtered_anomalies.json. 
        """
        filtered_anomalies = filter_df[filter_df["IsAnomaly"] == -1].copy()
        filtered_anomalies = filtered_anomalies.sort_values(by="AnomalyScore", ascending=True)  # Lower score = more anomalous

        anomaly_logs = []

        ##Append features and anomaly score to the log output.
        for idx, row in filtered_anomalies.iterrows():
            log_entry = all_data[idx]  # Get original log entry
            log_entry["PairFrequency"] = row["PairFrequency"] 
            log_entry["AnomalyScore"] = row["AnomalyScore"] 
            log_entry["ProcessCount"] = row["ProcessCount"] 
            log_entry["ParentProcessCount"] = row["ParentProcessCount"] 
            log_entry["ScaledAnomalyScore"] = row["ScaledAnomalyScore"]
            anomaly_logs.append(log_entry)
        
    
        ##Write anomalies to file. 
        with open("filtered_anomalies.json", "w", encoding="utf-8") as f: 
            json.dump(anomaly_logs, f, indent=4)

        print(f"There are: {len(filtered_anomalies)} anomalies after filtering") ##Print how many anomalies there are after filtering.



    else:
        print("No anomalies detected.")
        


    """    
    Graph various graphs:
    * Anomaly score distribution
    * Density plot
    * Barchart of Feature Correlation to Anomaly Score
    
    """
    if "AnomalyScore" in classification_df.columns:
        plt.figure(figsize=(10, 6))
        plt.hist(classification_df["AnomalyScore"], bins=100, color="skyblue", edgecolor="black")
        plt.title("Anomaly Score Distribution",fontsize=22)
        plt.xlabel("Anomaly Score",fontsize=20)
        plt.ylabel("Number of Logs",fontsize=20)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.grid(axis="y", alpha=0.75)
        plt.tight_layout()
        plt.show()

        ##Density plot of LOLBIN vs NON-LOLBIN
        plt.figure(figsize=(10, 6))
        sns.kdeplot(data=classification_df, x="AnomalyScore", hue="IsLOLBAS", common_norm=False, fill=True)
        plt.axvline(x=-0.01, color="red", linestyle="--", label="Anomaly Threshold")
        plt.title("Density Plot: Anomaly Score by LOLBIN vs. NON-LOLBIN",fontsize=22)
        plt.xlabel("Anomaly Score",fontsize=20)
        plt.ylabel("Density",fontsize=20)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend()
        plt.tight_layout()
        plt.savefig("Density_Plot_Anomaly_Score_LOLBIN_vs_NONLOLBIN.png", dpi=300, bbox_inches='tight')
        plt.show()
        

        
        correlations = classification_df[features + ["AnomalyScore"]].corr()["AnomalyScore"].drop("AnomalyScore")
        correlations.index = ["IsLOLBIN" if col == "IsLOLBAS" else col for col in correlations.index]

        # Barchart of feature corr with anomaly score. 
        plt.figure(figsize=(10, 6))
        sns.set_style("whitegrid")
        sns.barplot(x=correlations.values, y=correlations.index, palette="coolwarm")
        plt.title("Feature Correlation with Anomaly Score", fontsize=20)
        plt.xlabel("Correlation with Anomaly Score", fontsize=20)
        plt.ylabel("Feature", fontsize=20)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.savefig("feature_correlation.png", dpi=300, bbox_inches='tight')
        plt.show()

    else:
        print("'AnomalyScore' column not found in the DataFrame.")








"""
Check to see if the model file exists when running the program.
"""

if os.path.exists(MODEL_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            print(f"Loaded model from: {MODEL_FILE}")
        except (EOFError, joblib.externals.loky.process_executor._RemoteTraceback, joblib.externals.loky.process_executor.TerminatedWorkerError) as e:
            print(f"Error loading model file: {e}")
            model = None  # Prevent using an invalid model
else:
    print(f"Model file not found: {MODEL_FILE}")
    model = None



"""
Call classify_data to run the program and classify anomalies.

"""
print("Starting to detect anomalies")
classify_data(model)
