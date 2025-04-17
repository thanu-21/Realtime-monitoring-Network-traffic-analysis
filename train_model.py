import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# Random Sample Data Creation
np.random.seed(42)
data = pd.DataFrame({
    'protocol': np.random.randint(0, 3, size=100),
    'packet_length': np.random.randint(50, 1500, size=100),
    'ttl': np.random.randint(20, 255, size=100),
    'label': np.random.choice(['malicious', 'non-malicious'], size=100)
})

# Features and Labels
X = data[['protocol', 'packet_length', 'ttl']]
y = data['label']

# Model Training
model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# Model Save
joblib.dump(model, 'ml_model.joblib')
print(" Model created and saved as 'ml_model.joblib'")
