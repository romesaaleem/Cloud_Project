import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

class MLAnomalyDetector:
    def __init__(self):
        self.model_path = os.path.join('models', 'isolation_forest.pkl')
        self.clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self._bootstrap_model_if_absent()

    def _bootstrap_model_if_absent(self):
        if not os.path.exists(self.model_path):
            X_train = np.array([[1,0,1], [1,0,2], [2,0,1], [1,0,1], [1,1,5], [3,1,12], [4,1,20], [1,0,2]])
            self.clf.fit(X_train)
            joblib.dump(self.clf, self.model_path)
        else:
            self.clf = joblib.load(self.model_path)

    def predict_anomaly(self, event_type_id, failed_flag, continuous_frequency):
        features = np.array([[event_type_id, failed_flag, continuous_frequency]])
        prediction = self.clf.predict(features)
        score = self.clf.score_samples(features)
        return int(prediction[0]), float(abs(score[0]))