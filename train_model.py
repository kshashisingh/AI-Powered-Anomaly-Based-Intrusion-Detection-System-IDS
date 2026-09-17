import pandas as pd
import xgboost as xgb
import joblib
import json
from sklearn.preprocessing import LabelEncoder

# Load dataset
df = pd.read_csv("friday.csv")
df = df.dropna()

# Categorical feature columns
categorical_features = ["proto", "service"]

# Encode categorical features
encoders = {}
for col in categorical_features:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

# Features and label
top_features = [
    "proto", "service", "fwd_URG_flag_count",
    "fwd_pkts_payload.min", "fwd_pkts_payload.avg",
    "fwd_iat.max", "idle.min", "idle.avg",
    "fwd_init_window_size", "fwd_last_window_size"
]

X = df[top_features]
y = df["Attack_type"]

# Encode output label
le_y = LabelEncoder()
y_encoded = le_y.fit_transform(y)

# Train model
model = xgb.XGBClassifier()
model.fit(X, y_encoded)

# Save model and encoders
joblib.dump(model, 'model.pkl')
joblib.dump(le_y, 'label_encoder_y.pkl')
joblib.dump(encoders, 'input_encoders.pkl')  # contains proto + service encoders

with open('features.json', 'w') as f:
    json.dump(top_features, f)

print("? Training done and model saved.")
