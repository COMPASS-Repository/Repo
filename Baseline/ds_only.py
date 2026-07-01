import os
import pandas as pd
from openai import OpenAI, OpenAIError
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

INPUT_PATH = r"your file"
OUTPUT_PATH = r"your file"
API_KEY = ""
API_BASE_URL = ""
MODEL_NAME = ""
MAX_RETRIES = 1
RETRY_DELAY = 5
MAX_WORKERS = 1000

client = OpenAI(
    api_key=API_KEY,
    base_url=API_BASE_URL,
)


def process_row(index, row):
    prompt = row.prompt
    retries = 0
    while retries < MAX_RETRIES:
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                extra_body={"thinking": {"type": "disabled"}},
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


df = pd.read_csv(INPUT_PATH)

if not os.path.exists(OUTPUT_PATH):

    df1 = df[['cve','desc','prompt']].copy()
    df1['answer'] = ''
    df1.to_csv(OUTPUT_PATH, index=False)

df1 = pd.read_csv(OUTPUT_PATH).copy()


indices_to_process = []
print(f"Checking records to process... (total {len(df1)} records)")
for index, row in tqdm(df1.iterrows(), total=len(df1), desc="Checking"):
    if pd.isna(row['answer']) or row['answer'] == '':
        indices_to_process.append(index)

print(f"Number of records to process: {len(indices_to_process)}")

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = [executor.submit(process_row, index, df.loc[index]) for index in indices_to_process]
    for future in tqdm(as_completed(futures), total=len(futures), desc="Processing"):
        index, success, text = future.result()
        if success:
            df1.at[index, 'answer'] = text
            df1[['cve','desc','answer']].to_csv(OUTPUT_PATH, index=False)