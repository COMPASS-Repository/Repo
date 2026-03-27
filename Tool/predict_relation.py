import pandas as pd
import os
import re
import pandas as pd
from openai import OpenAI, OpenAIError
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
import ast


client = OpenAI(
    api_key="your key",
    base_url="https://api.deepseek.com",
)

MAX_RETRIES = 3
RETRY_DELAY = 5

def process_row(index, row):
    prompt = row.prompt
    retries = 0
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

    text = completion.choices[0].message.content
    return index, True, text

def generate_prompt_file(cve_name):

    df2 = pd.read_csv(f"./cache/{cve_name}.csv")
    df = pd.read_csv(f"./cache/{cve_name}_final.csv")
    df['branch'] = df['branches']

    df1 = df[['cve', 'commit', 'msg_text', 'diff_code', 'tags', 'branch', 'commit_time']]
    df1 = df1.merge(df2, on='cve')
    df1 = df1[['cve', 'desc', 'commit', 'diff_code', 'msg_text', 'tags', 'branch', 'commit_time']]
    grouped = df1.groupby('cve').agg({
        'commit': lambda group: '\n\n'.join([
            f"Commit {i + 1}:\n"
            f"Commit ID: {commit}\n"
            f"Commit Time: {time}\n"
            f"Message: {msg}\n"
            f"branch: {branch}\n"
            f"version: {tags}\n"
            f"Code diffs: {diff_code}"
            for i, (commit, diff_code, msg, branch, tags, time) in
            enumerate(zip(group, df1.loc[group.index, 'diff_code'], df1.loc[group.index, 'msg_text'],
                        df1.loc[group.index, 'branch'],
                        df1.loc[group.index, 'tags'],
                        df1.loc[group.index, 'commit_time']))
        ]),
        'desc': lambda x: x.iloc[0]
    }).reset_index()

    grouped['prompt'] = grouped.apply(generate_prompt, axis=1)

    output_file = f"./cache/{cve_name}_prompt_rq_eg.csv"
    grouped[['cve', 'desc', 'commit', 'prompt']].to_csv(output_file, index=False)
    print(f"Results saved to {output_file}")

def key_repl(m):
    key = m.group(1).strip().strip('"').strip("'")
    return "'{}':".format(key)

def parse_answer(answer_str):
    try:
        match = re.search(r'\{.*\}', answer_str, flags=re.DOTALL)
        if match:
            answer_str_clean = match.group(0)
        else:
            answer_str_clean = answer_str

        answer_str_clean = re.sub(
            r'([\'"]?6\. Separate[\'"]?)\s*:\s*\{\s*(\[[^\}]*\])\s*\}',
            r"\1: \2",
            answer_str_clean,
            flags=re.DOTALL
        )
        answer_str_clean = re.sub(
            r'([\'"]?\d+\.\s*[A-Za-z\-]+[\'"]?)\s*:',
            key_repl,
            answer_str_clean
        )
        answer_str_clean = re.sub(r'([}\]])\s*(?=\'[A-Za-z0-9\-\. ]+\'\:)', r'\1, ', answer_str_clean)
        answer_str_clean = re.sub(
            r'(?<=[\{\s:,])([a-fA-F0-9]{40})(?=\s*:)', r"'\1'", answer_str_clean
        )
        answer_str_clean = re.sub(
            r'(?<=[\[\s:,])([a-fA-F0-9]{40})(?=[,\]\}\s])', r"'\1'", answer_str_clean
        )
        parsed = ast.literal_eval(answer_str_clean)
        return parsed
    except Exception:
        return {}

relation_keys = [
    ('merge', '1. Merge'),
    ('mirror', '2. Mirror'),
    ('better', '3. Better'),
    ('fix-of', '4. Fix-of'),
    ('collab', '5. Collab'),
    ('separate', '6. Separate'),
]

def extract_relations(row):
    parsed = parse_answer(row['answer'])
    result = {}
    for col, dict_key in relation_keys:
        val = parsed.get(dict_key)
        result[col] = val
    return pd.Series(result)

def predict_relations(cve_name):
    output_path = f"./cache/{cve_name}_relations.csv"
    df = pd.read_csv(f"./cache/{cve_name}_prompt_rq_eg.csv")
    print(f"Dataset size: {len(df)}")
    if not os.path.exists(output_path):
        df1 = df[['cve','desc','prompt']].copy()
        df1['answer'] = ''
        df1.to_csv(output_path, index=False)
    df1 = pd.read_csv(output_path).copy()

    indices_to_process = []
    for index, row in df1.iterrows():
        if pd.isna(row['answer']) or row['answer'] == '':
            indices_to_process.append(index)

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(process_row, index, df.loc[index]) for index in indices_to_process]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing"):
            index, success, text = future.result()
            if success:
                df1.at[index, 'answer'] = text
                df1[['cve','desc','answer']].to_csv(output_path, index=False)
    
    df = pd.read_csv(output_path).copy()
    df[[k for k, _ in relation_keys]] = df.apply(extract_relations, axis=1)
    df.to_csv(f"./cache/{cve_name}_graph.csv", index=False)


def generate_prompt(row):
    max_length = 60000
    base_prompt = (
           f"Role: You are a senior security analyst specializing in vulnerability patching patterns. \n"
            "\n"
            "Task: Analyze multiple Git commits associated with a CVE and predict their relationships according to typical patterns.\n"
            "\n"
            "Input Data:\n"
            "- CVE ID and description\n"
            "- All commits in the patch group (Commit IDs and Messages, Branch/Versions information, Code diffs)\n"
            "\n"
            "Requirements: For each commit\n"
            "     a. Determine if it indeed fixes the CVE directly.\n"
            "     b. Identify key components/files modified.\n"
            "     c. Note any implicit signals available in commit messages and branch/version information (e.g., refinement-oriented wording or version-specific context).\n"
            "First, analyze the following two relationships for commits in the patch group:\n"
            "\n"
            "1. Merge: A patch consolidates the effects of multiple related patches on separate development lines. Code changes should satisfy the condition that Merge patch codes are composed of Merged patches codes. Note that distinguish between Merge patch (the parent commit integrating changes) and Merged patches (original changes being integrated)\n"
            "[Output Schema] R_ID-“Merge”: {Merge_patch: [Merged_patch1, Merged_patch2, ...], ...}\n"
            "\n"
            "2. Mirror: Patches with identical/similar fixes for different software versions (e.g., Ver 4.1, Ver 5.2, ...) or branches (e.g., Br main, Br release-X.Y, ...). Commit messages and code changes should show great similarity.\n"
            "[Output Schema] R_ID-“Mirror”: {PrimaryVer_patch: [Ver1_patch, Ver2_patch, ...], ...}, {MainBr_patch: [Br1_patch, Br2_patch, ...], ...}\n"
            "\n"
            "Then, identify the following three relationships further. Note that the dependency of patches is the foundation for forming these relationships. A dependency between two patches means:\n"
            "    - The modifications in the subsequent patch need to be based on the code of the previous patch.\n"
            "    - The subsequent patch needs to use the newly added or modified functions, variables, etc. from the previous patch.\n"
            "    - The order of the two patches can affect the logic or functionality of the code and the fixing effectiveness.\n"
            "\n"
            "3. Better solution: A following patch 1) aims to improve the readability, running efficiency, etc. of the previous patch without affecting security, or 2) only modifies text information (e.g., comments) without code changing, or 3) can replace the refined part of the previous patch's vulnerability-fixing logic. Messages of following patches are often obtained by making slight modifications to messages of the previous patch. Code changes should satisfy the condition that a following patch delete some codes from the previous patch and replace them with codes of the same security level, or just adds comments, etc.\n"
            "[Output Schema] R_ID-“Better Solution”: {Original_patch: [Better_patch, ...], ...}\n"
            "\n"
            "4. Fixing-of-Fixing: A following patch 1) fixes the issues introduced by the previous patch, such as incorrect fixing logic, inappropriate function or variable names, or regular expression errors, etc., or 2) backports the code to the previous version without errors, or 3) deletes incorrect calls or definitions. Distinguish it from that the subsequent patch fixes the parts that were not resolved in the previous patch.\n"
            "[Output Schema] R_ID-“Fixing-of-Fixing”: {Flawed_patch: [Corrected_patch, ...], ...}\n"
            "\n"
            "5. Collaboration: The previous patch 1) cannot completely solve all the problems, or 2) prepares for the fixes in the subsequent patch such as defining functions. All patches are required for complete vulnerability remediation.\n"
            "[Output Schema] R_ID-“Collaboration”: {Previous_patch: [Subsequent_patch, ...], ...}\n"
            "\n"
            "Last, if there is no dependency between two patches, consider the following relationship:\n"
            "\n"
            "6. Separation: Patches contribute to remediation without dependency, their application order does not affect fixing effectiveness. The patches 1) address different aspects of the vulnerability independently, or 2) perform fixes at multiple code locations where the vulnerable pattern is replicated.\n"            
            "[Output Schema] R_ID-“Separation”: {Patch1}, R_ID-“Separation”: {Patch2}, ...\n"
            "\n"
            "Ensure every patch in the input patch group should participate in at least one relationship instance, except for patches that have been identified in Phase-2 as not contributing to the target vulnerability.\n"
            "Verify no contradictory relationships\n"
            "- Relationship instances in Hierarchy-1 (Merge and Mirror) should be single-labeled\n"
            "- The instances in Hierarchy-2 (Better Solution, Fixing-of-Fixing, and Collaboration) may carry multiple labels, \n"
            "- For Hierarchy-3 (Separation), each instance is single-labeled\n"
            f"CVE ID:{row['cve']}\n"
            "\n"
            "CVE Description:\n"
            f"{row['desc']}\n"
            "\n"
            f"{row['commit']}"
    )

    if len(base_prompt) > max_length:
        excess_length = len(base_prompt) - max_length
        import re
        commit_pattern = re.compile(r'Code diffs: (.*?)(?=Commit \d+|$)', re.DOTALL)
        diff_codes = commit_pattern.findall(row['commit'])
        total_diff_length = sum(len(diff) for diff in diff_codes)
        reduction_factors = [len(diff) / total_diff_length for diff in diff_codes]
        reduced_diff_codes = []
        for diff, factor in zip(diff_codes, reduction_factors):
            reduction_length = int(factor * excess_length)
            reduced_diff = diff[:len(diff) - reduction_length]
            reduced_diff = reduced_diff + '"'
            reduced_diff_codes.append(reduced_diff)
        new_commit = commit_pattern.sub(lambda m: f"Code diffs: {reduced_diff_codes.pop(0)}", row['commit'])
        prompt = (
            f            "Role: You are a senior security analyst specializing in vulnerability patching patterns. \n"
            "\n"
            "Task: Analyze multiple Git commits associated with a CVE and predict their relationships according to typical patterns.\n"
            "\n"
            "Input Data:\n"
            "- CVE ID and description\n"
            "- All commits in the patch group (Commit IDs and Messages, Branch/Versions information, Code diffs)\n"
            "\n"
            "Requirements: For each commit\n"
            "     a. Determine if it indeed fixes the CVE directly.\n"
            "     b. Identify key components/files modified.\n"
            "     c. Note any implicit signals available in commit messages and branch/version information (e.g., refinement-oriented wording or version-specific context).\n"
            "First, analyze the following two relationships for commits in the patch group:\n"
            "\n"
            "1. Merge: A patch consolidates the effects of multiple related patches on separate development lines. Code changes should satisfy the condition that Merge patch codes are composed of Merged patches codes. Note that distinguish between Merge patch (the parent commit integrating changes) and Merged patches (original changes being integrated)\n"
            "[Output Schema] R_ID-“Merge”: {Merge_patch: [Merged_patch1, Merged_patch2, ...], ...}\n"
            "\n"
            "2. Mirror: Patches with identical/similar fixes for different software versions (e.g., Ver 4.1, Ver 5.2, ...) or branches (e.g., Br main, Br release-X.Y, ...). Commit messages and code changes should show great similarity.\n"
            "[Output Schema] R_ID-“Mirror”: {PrimaryVer_patch: [Ver1_patch, Ver2_patch, ...], ...}, {MainBr_patch: [Br1_patch, Br2_patch, ...], ...}\n"
            "\n"
            "Then, identify the following three relationships further. Note that the dependency of patches is the foundation for forming these relationships. A dependency between two patches means:\n"
            "    - The modifications in the subsequent patch need to be based on the code of the previous patch.\n"
            "    - The subsequent patch needs to use the newly added or modified functions, variables, etc. from the previous patch.\n"
            "    - The order of the two patches can affect the logic or functionality of the code and the fixing effectiveness.\n"
            "\n"
            "3. Better solution: A following patch 1) aims to improve the readability, running efficiency, etc. of the previous patch without affecting security, or 2) only modifies text information (e.g., comments) without code changing, or 3) can replace the refined part of the previous patch's vulnerability-fixing logic. Messages of following patches are often obtained by making slight modifications to messages of the previous patch. Code changes should satisfy the condition that a following patch delete some codes from the previous patch and replace them with codes of the same security level, or just adds comments, etc.\n"
            "[Output Schema] R_ID-“Better Solution”: {Original_patch: [Better_patch, ...], ...}\n"
            "\n"
            "4. Fixing-of-Fixing: A following patch 1) fixes the issues introduced by the previous patch, such as incorrect fixing logic, inappropriate function or variable names, or regular expression errors, etc., or 2) backports the code to the previous version without errors, or 3) deletes incorrect calls or definitions. Distinguish it from that the subsequent patch fixes the parts that were not resolved in the previous patch.\n"
            "[Output Schema] R_ID-“Fixing-of-Fixing”: {Flawed_patch: [Corrected_patch, ...], ...}\n"
            "\n"
            "5. Collaboration: The previous patch 1) cannot completely solve all the problems, or 2) prepares for the fixes in the subsequent patch such as defining functions. All patches are required for complete vulnerability remediation.\n"
            "[Output Schema] R_ID-“Collaboration”: {Previous_patch: [Subsequent_patch, ...], ...}\n"
            "\n"
            "Last, if there is no dependency between two patches, consider the following relationship:\n"
            "\n"
            "6. Separation: Patches contribute to remediation without dependency, their application order does not affect fixing effectiveness. The patches 1) address different aspects of the vulnerability independently, or 2) perform fixes at multiple code locations where the vulnerable pattern is replicated.\n"            
            "[Output Schema] R_ID-“Separation”: {Patch1}, R_ID-“Separation”: {Patch2}, ...\n"
            "\n"
            "Ensure every patch in the input patch group should participate in at least one relationship instance, except for patches that have been identified in Phase-2 as not contributing to the target vulnerability.\n"
            "Verify no contradictory relationships\n"
            "- Relationship instances in Hierarchy-1 (Merge and Mirror) should be single-labeled\n"
            "- The instances in Hierarchy-2 (Better Solution, Fixing-of-Fixing, and Collaboration) may carry multiple labels, \n"
            "- For Hierarchy-3 (Separation), each instance is single-labeled\n"
            f"CVE ID:{row['cve']}\n"
            "\n"
            "CVE Description:\n"
            f"{row['desc']}\n"
            "\n"
            f"{row['commit']}"
        )
    else:
        prompt = base_prompt

    return prompt


if __name__ == "__main__":
    cve_name = "your cve"
    generate_prompt_file(cve_name)
    predict_relations(cve_name)
