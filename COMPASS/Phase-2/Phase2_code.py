import os
import pandas as pd
from openai import OpenAI, OpenAIError
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


client = OpenAI(
    api_key="your_key",
    base_url="your_url"
)

MAX_RETRIES = 1
RETRY_DELAY = 5


def process_row(index, row):
    prompt = row.prompt
    retries = 0
    while retries < MAX_RETRIES:
        try:
            completion = client.chat.completions.create(
                model=" chose_your_model",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            break
        except OpenAIError as e:
            retries += 1
            time.sleep(RETRY_DELAY)
        except Exception as e:
            break
    else:
        return index, False, ''

    text = completion.choices[0].message.content
    return index, True, text


output_path = "output_path"
df = pd.read_csv("dataset_path")

if not os.path.exists(output_path):

    df1 = df[['cve','desc','prompt']].copy()
    df1['answer'] = ''
    df1.to_csv(output_path, index=False)

df1 = pd.read_csv(output_path).copy()


indices_to_process = []
for index, row in df1.iterrows():
    if pd.isna(row['answer']) or row['answer'] == '':
        indices_to_process.append(index)

with ThreadPoolExecutor(max_workers=40) as executor:
    futures = [executor.submit(process_row, index, df.loc[index]) for index in indices_to_process]
    for future in tqdm(as_completed(futures), total=len(futures), desc="Processing"):
        index, success, text = future.result()
        if success:
            df1.at[index, 'answer'] = text
            df1[['cve','desc','answer']].to_csv(output_path, index=False)
