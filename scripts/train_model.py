import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
import os

# 1. Load Data (Ensure KDDTrain+.txt is in your folder)
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
           "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
           "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
           "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", 
           "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", 
           "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
           "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
           "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
           "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
           "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "difficulty_level"]

df = pd.read_csv(r"C:\Users\Laxman\Downloads\archive\KDDTrain+.txt", names=columns)

# 2. Attack Mapping
mapping = {
    'ipsweep': 'Probe','satan': 'Probe','nmap': 'Probe','portsweep': 'Probe','saint': 'Probe','mscan': 'Probe',
    'teardrop': 'DoS','pod': 'DoS','land': 'DoS','back': 'DoS','neptune': 'DoS','smurf': 'DoS','mailbomb': 'DoS','udpstorm': 'DoS','apache2': 'DoS','processtable': 'DoS',
    'perl': 'U2R','loadmodule': 'U2R','rootkit': 'U2R','buffer_overflow': 'U2R','xterm': 'U2R','ps': 'U2R','sqlattack': 'U2R',
    'ftp_write': 'R2L','phf': 'R2L','guess_passwd': 'R2L','warezmaster': 'R2L','warezclient': 'R2L','imap': 'R2L','spy': 'R2L','multihop': 'R2L','named': 'R2L',
    'normal': 'Normal'
}
df['attack_category'] = df['attack_type'].map(mapping).fillna('Other')

# 3. Categorical Encoding
encoders = {}
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

target_le = LabelEncoder()
df['attack_category'] = target_le.fit_transform(df['attack_category'])

# 4. Prepare Features & SAVE MEANS
X = df.drop(['attack_type', 'difficulty_level', 'attack_category'], axis=1)
y = df['attack_category']
feature_means = X.mean(axis=0).values # CRITICAL: Save means for App.py

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5. Train with Balanced Weights (The "Normal" bypass fix)
model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
model.fit(X_scaled, y)

# 6. Save Everything
if not os.path.exists('model'): os.makedirs('model')
joblib.dump(model, "model/ids_multi_model.pkl")
joblib.dump(scaler, "model/scaler.pkl")
joblib.dump(encoders, "model/encoders.pkl")
joblib.dump(target_le, "model/target_encoder.pkl")
joblib.dump(feature_means, "model/feature_means.pkl")

print("✅ Training complete with balanced weights!")