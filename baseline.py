import json

def load_baseline(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_baseline(stats, path):
    with open(path, "w") as f:
        json.dump(stats, f, indent=2)