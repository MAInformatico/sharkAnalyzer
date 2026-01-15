import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib


class AnomalyAgent:
    """Agente de detección de anomalías basado en IsolationForest.

    Uso esperado:
    - Entrenar con `fit(X)` donde `X` es un DataFrame o array-like de features.
    - Detectar con `predict(X)` que devuelve 1 para anómalo y 0 para normal.
    - Persistir con `save(path)` y `load(path)`.
    """

    def __init__(self, n_estimators=100, contamination='auto', random_state=42, model_path=None):
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
        self.model_path = model_path

    def fit(self, X):
        X = self._prep(X)
        self.model.fit(X)
        return self

    def predict(self, X):
        X = self._prep(X)
        preds = self.model.predict(X)
        # IsolationForest devuelve -1 (anómalo) o 1 (normal)
        return np.where(preds == -1, 1, 0)

    def score_samples(self, X):
        X = self._prep(X)
        return self.model.score_samples(X)

    def fit_predict(self, X):
        self.fit(X)
        return self.predict(X)

    def save(self, path=None):
        path = path or self.model_path
        if not path:
            raise ValueError('Se requiere `path` para guardar el modelo.')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)

    def load(self, path):
        self.model = joblib.load(path)
        self.model_path = path

    def _prep(self, X):
        if isinstance(X, pd.DataFrame):
            return X.values
        return np.asarray(X)


def extract_features_from_records(records):
    """Convierte una lista de registros (dicts) en un DataFrame numérico.

    Espera campos numéricos como `bytes`, `packets`, `duration`, y opcionalmente `protocol`.
    Si `protocol` es categórico, codifica a números.
    """
    df = pd.DataFrame(records)
    if 'protocol' in df.columns:
        df['protocol'] = df['protocol'].astype('category').cat.codes
    numeric = df.select_dtypes(include=[np.number])
    return numeric.fillna(0)


if __name__ == '__main__':
    # Demo mínimo: generar datos normales y algunos anómalos
    rng = np.random.RandomState(42)
    normal = rng.normal(loc=0.0, scale=1.0, size=(200, 3))
    anomalies = rng.normal(loc=8.0, scale=0.5, size=(5, 3))
    X = np.vstack([normal, anomalies])

    agent = AnomalyAgent(n_estimators=100, contamination=0.02)
    agent.fit(X)
    preds = agent.predict(X)
    print('Anomalías detectadas:', preds.sum())
