import pandas as pd
import os
import re
from openai import OpenAI, OpenAIError
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time


def generate_deepseek_analysis(cve_name, api_key="your key", 
                              base_url="https://api.deepseek.com", max_workers=25,
                              input_file_suffix="_top50.csv", cache_dir="./cache"):
    
    print(f"Start processing CVE: {cve_name}")
    
    input_file = f'{cache_dir}/{cve_name}{input_file_suffix}'
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file does not exist: {input_file}")

    new_df = pd.read_csv(input_file)

    new_df['msg_text'] = new_df['msg_text'].fillna('')
    new_df['diff_code'] = new_df['diff_code'].fillna('')
    new_df['cwe'] = new_df['cwe'].apply(eval)
    new_df['cwe'] = new_df['cwe'].apply(lambda x: [t[1] for t in x] if x else [])
    new_df['cwe'] = new_df['cwe'].apply(lambda x: [] if all(item == 'Other' for item in x) else x)

    for index, row in new_df.iterrows():
        diff_code = row['diff_code']
        if len(diff_code) > 50000:
            diff_code = diff_code[:50000]

        if len(row['cwe']) == 0:
            user_prompt = "you prompt"
        elif len(row['cwe']) == 1:
            user_prompt =  "you prompt"
        elif len(row['cwe']) > 1:
            result = ', '.join(row['cwe'])
            user_prompt = "you prompt"
          
        new_df.at[index, 'prompt'] = user_prompt

    new_df = new_df[['cve', 'commit', 'prompt']]

    client = OpenAI(
        api_key=api_key,
        base_url=base_url
    )

    MAX_RETRIES = 3
    RETRY_DELAY = 5

    def process_row(index, row):
        prompt = row.prompt
        if len(prompt) > 64000:
            prompt = prompt[:64000]
        
        retries = 0
        completion = ''
        
        while retries < MAX_RETRIES:
            try:
                completion = client.chat.completions.create(
                    model="deepseek-chat",
                    store=True,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                break
            except OpenAIError as e:
                print(f"API call error on row {index}: {e}, retrying {retries + 1}...")
                retries += 1
                time.sleep(RETRY_DELAY)
            except Exception as e:
                print(f"Non-API exception on row {index}: {e}, no more retries")
                break
        else:
            print(f"Request on row {index} failed after {MAX_RETRIES} retries")
            return index, False, ''

        if completion == '':
            return index, False, ''

        text = completion.choices[0].message.content
        return index, True, text

    def parse_json_response(text):
        try:
            patterns = [
                r'({.*?})',
                r'```json\s*({.*?})\s*```',
                r'```\s*({.*?})\s*```',
                r'(\{[^{}]*"summarization"[^{}]*\})',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, text, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return data
            
            if text.strip().startswith('{') and text.strip().endswith('}'):
                data = json.loads(text.strip())
                return data
                
        except (json.JSONDecodeError, AttributeError):
            return None
        
        return None

    def process_row_with_json_retry(index, row, max_api_retries=3):
        for attempt in range(max_api_retries):
            api_index, success, text = process_row(index, row)
            
            if not success:
                print(f"API call failed on row {index}, attempt {attempt + 1}/{max_api_retries}")
                if attempt < max_api_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return index, False, '', None
            
            parsed_data = parse_json_response(text)
            if parsed_data:
                return index, True, text, parsed_data
            else:
                print(f"JSON parsing failed on row {index}, re-calling API (attempt {attempt + 1}/{max_api_retries})")
                if attempt < max_api_retries - 1:
                    time.sleep(2)
                    continue
        
        print(f"Row {index} failed to get valid JSON response after {max_api_retries} API calls")
        return index, False, text if 'text' in locals() else '', None

    final_output = f'{cache_dir}/{cve_name}-deepseek.csv'

    if not os.path.exists(final_output):
        df_result = new_df[['cve', 'commit']].copy()
        df_result['answer'] = ''
        df_result['summarization'] = ''
        df_result['potential_addressed_vulnerability_types'] = ''
        df_result['is_patch'] = ''
        df_result.to_csv(final_output, index=False)

    df_result = pd.read_csv(final_output)
    df_result['summarization'] = df_result['summarization'].astype('string')
    df_result['potential_addressed_vulnerability_types'] = df_result['potential_addressed_vulnerability_types'].astype('string')
    df_result['is_patch'] = df_result['is_patch'].astype('string')
    df_result['answer'] = df_result['answer'].astype('string')

    df_prompt = new_df
    df_combined = df_result.merge(df_prompt, on=['cve', 'commit'], how='left')

    indices_to_process = []
    for index, row in df_combined.iterrows():
        if pd.isna(row['answer']) or row['answer'] == '':
            indices_to_process.append(index)

    print(f'Total rows of data: {len(df_combined)}')
    print(f'Rows to process: {len(indices_to_process)}')

    if len(indices_to_process) > 0:
        print('Start calling DeepSeek API...', time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_row_with_json_retry, index, df_combined.loc[index]) for index in indices_to_process]
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Processing all data"):
                index, success, text, parsed_data = future.result()
                if success and parsed_data:
                    df_combined.at[index, 'answer'] = text
                    df_combined.at[index, 'summarization'] = parsed_data.get('summarization', '')
                    df_combined.at[index, 'potential_addressed_vulnerability_types'] = str(parsed_data.get('potential addressed vulnerability types', []))
                    df_combined.at[index, 'is_patch'] = parsed_data.get('is_patch', '')
                elif success:
                    df_combined.at[index, 'answer'] = text
                    print(f"JSON parsing failed on row {index}, but raw response saved")
                else:
                    print(f"Row {index} processing failed completely")
        
        result_cols = ['cve', 'commit', 'answer', 'summarization', 'potential_addressed_vulnerability_types', 'is_patch']
        df_combined[result_cols].to_csv(final_output, index=False)

    print(f'All data processing completed, results saved to: {final_output}')
    
    result_cols = ['cve', 'commit', 'answer', 'summarization', 'potential_addressed_vulnerability_types', 'is_patch']
    return df_combined[result_cols]


if __name__ == "__main__":
    cve_name = "your cve"
    result_df = generate_deepseek_analysis(cve_name)
    print("Analysis completed!")
