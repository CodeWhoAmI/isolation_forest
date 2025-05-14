# isolation_forest
Code to create a machine learning model based on the isolation forest algorithm to do anomaly detection of LotL on sysmon process create logs using parent-child relationships. 

Consists of:

Isolation_forest_trainin.py - To do training of the model, and export a .pkl file with the trained model.

Classification_predict.py - Use this to classify with the predict method of the isolation forest library by sci-kit learn.

Classification_decision_boundary.py - Used to create a manual decision boundary based on the anomaly score (scaled) to the most anomalous log. Can be tuned and adjusted using the threshold. 
