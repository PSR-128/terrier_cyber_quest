import pandas as pd

train_data = pd.read_parquet("hf://datasets/vyykaaa/dataset-v2/data/train-00000-of-00001.parquet")

print(train_data.head())