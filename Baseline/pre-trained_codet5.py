import os
os.environ['CUDA_VISIBLE_DEVICES'] = '4'
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModel, PreTrainedModel, AutoConfig, T5EncoderModel
from sklearn.model_selection import KFold, train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import numpy as np
from tqdm import tqdm
import warnings
import random
import ast
from collections import defaultdict
from sklearn.metrics import precision_score, recall_score, f1_score

warnings.filterwarnings('ignore')

def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
set_seed(42)

MAX_LENGTH = 512
BATCH_SIZE = 16
EPOCHS = 20
LEARNING_RATE = 2e-5
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_NAME = "codet5"
LABEL_NAMES = ['merge', 'mirror', 'better', 'fix-of', 'collab', 'separate']
SAVE_DIR = '../venn_models_finetune_codet5'
NUM_FOLDS = 10

os.makedirs(SAVE_DIR, exist_ok=True)

def clean_text(text):
    if not isinstance(text, str):
        return ""
    return text[:10000]

def prepare_dataset():
    labels_df = pd.read_csv('../label.csv')
    try:
        commit_details_df = pd.read_csv('../commit_details.csv')
    except FileNotFoundError:
        print("Error: commit_details.csv not found.")
        return []

    commit_info = {}
    for _, row in commit_details_df.iterrows():
        commit_id = row.get('commit_hash', row.get('commit'))
        if pd.isna(commit_id):
            continue

        msg_text = row.get('message', row.get('msg_text', ''))
        diff_code = row.get('diff_code', '')
        commit_time = row.get('commit_time', '')
        branch = row.get('branch', '')
        tags = row.get('tags', '')

        try:
            msg_text = clean_text(msg_text)
            diff_code = clean_text(diff_code)
            text = (
                f"Commit ID: {commit_id}\n"
                f"Commit Time: {commit_time}\n"
                f"Branch: {branch}\n"
                f"Version: {tags}\n"
                f"Message: {msg_text}\n"
                f"Code Diff: {diff_code}"
            )
            short_id = str(commit_id).strip()[:7]
            commit_info[short_id] = text
        except Exception:
            pass

    dataset = []
    for _, row in labels_df.iterrows():
        commit1_short = str(row['commit1']).strip()[:7]
        commit2_short = str(row['commit2']).strip()[:7]

        text1 = commit_info.get(commit1_short)
        text2 = commit_info.get(commit2_short)

        if text1 and text2:
            combined_text = text1 + " [SEP] " + text2
            labels = [row['merge'], row['mirror'], row['better'], row['fix-of'], row['collab'], row['separate']]
            dataset.append({
                'text': combined_text,
                'labels': labels,
                'commit1': commit1_short,
                'commit2': commit2_short,
                'cve': row.get('cve', ''),
                'repo': row.get('repo', '')
            })

    print(f"Prepared dataset with {len(dataset)} samples (from {len(labels_df)} labels and {len(commit_details_df)} details).")
    return dataset

class CommitPairDataset(Dataset):
    def __init__(self, data, tokenizer, max_length):
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length
    def __len__(self):
        return len(self.data)
    def __getitem__(self, idx):
        item = self.data[idx]
        text = item['text']
        labels = torch.tensor(item['labels'], dtype=torch.float)
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding='max_length',
            return_tensors='pt'
        )
        return {
            'input_ids': encoding['input_ids'].squeeze(),
            'attention_mask': encoding['attention_mask'].squeeze(),
            'labels': labels,
            'commit1': item['commit1'],
            'commit2': item['commit2'],
            'cve': item.get('cve', ''),
            'repo': item.get('repo', '')
        }

class BertForMultiLabelClassification(PreTrainedModel):
    def __init__(self, config, num_labels=6):
        super().__init__(config)
        self.config = config

        if config.model_type == 't5':
            from transformers import T5EncoderModel
            try:
                self.bert = T5EncoderModel(config)
            except:
                self.bert = AutoModel.from_config(config)
        else:
            self.bert = AutoModel.from_config(config)

        self.num_labels = num_labels
        self.classifier = torch.nn.Linear(config.hidden_size, num_labels)
        self.post_init()

    def forward(self, input_ids, attention_mask=None, labels=None):
        if self.config.model_type == 't5':
            try:
                outputs = self.bert(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                )
                if hasattr(outputs, 'encoder_last_hidden_state'):
                    last_hidden_state = outputs.encoder_last_hidden_state
                else:
                    last_hidden_state = outputs.last_hidden_state
            except TypeError:
                outputs = self.bert(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                )
                last_hidden_state = outputs.last_hidden_state

            if attention_mask is not None:
                mask_expanded = attention_mask.unsqueeze(-1).expand(last_hidden_state.size())
                sum_embeddings = torch.sum(last_hidden_state * mask_expanded, 1)
                sum_mask = torch.clamp(mask_expanded.sum(1), min=1e-9)
                pooled_output = sum_embeddings / sum_mask
            else:
                pooled_output = torch.mean(last_hidden_state, dim=1)
        else:
            outputs = self.bert(
                input_ids=input_ids,
                attention_mask=attention_mask
            )
            if hasattr(outputs, 'pooler_output') and outputs.pooler_output is not None:
                pooled_output = outputs.pooler_output
            else:
                pooled_output = outputs.last_hidden_state[:, 0, :]

        logits = self.classifier(pooled_output)

        loss = None
        if labels is not None:
            loss = torch.nn.functional.binary_cross_entropy_with_logits(logits, labels)
        return type('Output', (), {'logits': logits, 'loss': loss})

class WeightedFocalLoss(torch.nn.Module):
    def __init__(self, gamma=2.0, class_weights=None):
        super().__init__()
        self.gamma = gamma
        self.class_weights = class_weights
    def forward(self, inputs, targets):
        BCE_loss = torch.nn.functional.binary_cross_entropy_with_logits(inputs, targets, reduction='none')
        pt = torch.exp(-BCE_loss)
        if self.class_weights is not None:
            weights = targets * self.class_weights[None, :] + (1 - targets) * 1.0
            F_loss = weights * (1-pt)**self.gamma * BCE_loss
        else:
            F_loss = (1-pt)**self.gamma * BCE_loss
        return F_loss.mean()

def train_epoch(model, data_loader, optimizer, criterion, device):
    model.train()
    epoch_loss = 0
    for batch in tqdm(data_loader, desc="Training"):
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)
        optimizer.zero_grad()
        outputs = model(input_ids, attention_mask, labels)
        logits = outputs.logits
        loss = criterion(logits, labels)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()
    return epoch_loss / len(data_loader)

def find_optimal_thresholds(all_probs, all_labels):
    best_thresholds = []
    for i, label_name in enumerate(LABEL_NAMES):
        y_prob = all_probs[:, i]
        y_true = all_labels[:, i]
        positive_count = np.sum(y_true)
        if positive_count == 0 or positive_count == len(y_true):
            best_thresholds.append(0.5)
            continue
        best_f1 = 0
        best_threshold = 0.5
        thresholds = np.arange(0.01, 1.0, 0.01)
        for threshold in thresholds:
            y_pred = (y_prob >= threshold).astype(int)
            _, _, f1, _ = precision_recall_fscore_support(
                y_true, y_pred, average='binary', zero_division=0
            )
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
        best_thresholds.append(best_threshold)
    return best_thresholds

def evaluate_model(model, data_loader, criterion, device, thresholds=None, verbose=True):
    model.eval()
    eval_loss = 0
    all_probs = []
    all_labels = []
    with torch.no_grad():
        for batch in tqdm(data_loader, desc="Evaluating"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            outputs = model(input_ids, attention_mask, labels)
            logits = outputs.logits
            loss = criterion(logits, labels)
            eval_loss += loss.item()
            probs = torch.sigmoid(logits).cpu().numpy()
            all_probs.extend(probs)
            all_labels.extend(labels.cpu().numpy())
    avg_loss = eval_loss / len(data_loader)
    all_probs = np.array(all_probs)
    all_labels = np.array(all_labels)
    if thresholds is None:
        thresholds = find_optimal_thresholds(all_probs, all_labels)
    all_preds = np.zeros_like(all_probs, dtype=int)
    for i in range(all_probs.shape[1]):
        all_preds[:, i] = (all_probs[:, i] >= thresholds[i]).astype(int)
    results = {}
    for i, label_name in enumerate(LABEL_NAMES):
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels[:, i], all_preds[:, i], average='binary', zero_division=0
        )
        accuracy = accuracy_score(all_labels[:, i], all_preds[:, i])
        results[label_name] = {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'accuracy': accuracy,
            'threshold': thresholds[i]
        }
    overall_precision, overall_recall, overall_f1, _ = precision_recall_fscore_support(
        all_labels.flatten(), all_preds.flatten(), average='binary', zero_division=0
    )
    overall_accuracy = accuracy_score(all_labels.flatten(), all_preds.flatten())
    results['overall'] = {
        'precision': overall_precision,
        'recall': overall_recall,
        'f1': overall_f1,
        'accuracy': overall_accuracy,
        'loss': avg_loss,
        'thresholds': thresholds
    }
    return results, all_preds, all_labels, thresholds

def train_and_evaluate_10fold():
    full_dataset = prepare_dataset()
    if len(full_dataset) < 2:
        print("Dataset too small for training.")
        return {}, {}, []

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    n_splits = NUM_FOLDS
    if len(full_dataset) < NUM_FOLDS:
        print(f"Warning: Dataset size ({len(full_dataset)}) is smaller than NUM_FOLDS ({NUM_FOLDS}). Adjusting n_splits to {len(full_dataset)}.")
        n_splits = len(full_dataset)

    kf = KFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_results = []
    all_fold_metrics = {label: {'precision': [], 'recall': [], 'f1': [], 'accuracy': [], 'threshold': []} for label in LABEL_NAMES}
    all_fold_metrics['overall'] = {'precision': [], 'recall': [], 'f1': [], 'accuracy': []}
    for fold, (train_val_idx, test_idx) in enumerate(kf.split(full_dataset)):
        print(f"\n===== Fold {fold+1}/{NUM_FOLDS} =====")
        fold_train_val_data = [full_dataset[i] for i in train_val_idx]
        fold_test_data = [full_dataset[i] for i in test_idx]
        fold_train_data, fold_val_data = train_test_split(
            fold_train_val_data, test_size=1/9, random_state=42
        )
        train_labels = np.array([item['labels'] for item in fold_train_data])
        class_weights = torch.ones(len(LABEL_NAMES), dtype=torch.float).to(DEVICE)
        train_dataset = CommitPairDataset(fold_train_data, tokenizer, MAX_LENGTH)
        val_dataset = CommitPairDataset(fold_val_data, tokenizer, MAX_LENGTH)
        test_dataset = CommitPairDataset(fold_test_data, tokenizer, MAX_LENGTH)
        train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, num_workers=2)
        val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, num_workers=2)
        test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, num_workers=2)

        config = AutoConfig.from_pretrained(MODEL_NAME)
        model = BertForMultiLabelClassification(config, num_labels=len(LABEL_NAMES))
        model.to(DEVICE)
        optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)
        criterion = WeightedFocalLoss(gamma=2.0, class_weights=class_weights)
        best_val_f1 = 0
        best_model_path = os.path.join(SAVE_DIR, f'model_fold_{fold+1}.pt')
        best_val_thresholds = None
        for epoch in range(EPOCHS):
            print(f"Epoch {epoch+1}/{EPOCHS}")
            train_loss = train_epoch(model, train_loader, optimizer, criterion, DEVICE)
            print(f"Train loss: {train_loss:.4f}")
            val_results, _, _, val_thresholds = evaluate_model(
                model, val_loader, criterion, DEVICE
            )
            val_f1 = val_results['overall']['f1']
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                torch.save(model.state_dict(), best_model_path)
                best_val_thresholds = val_thresholds
        print(f"Best val F1: {best_val_f1:.4f}")
        model.load_state_dict(torch.load(best_model_path))
        test_results, test_preds, _, _ = evaluate_model(
            model, test_loader, criterion, DEVICE, best_val_thresholds
        )

        for label_name in LABEL_NAMES + ['overall']:
            for metric in ['precision', 'recall', 'f1', 'accuracy']:
                all_fold_metrics[label_name][metric].append(test_results[label_name][metric])
            if label_name != 'overall':
                all_fold_metrics[label_name]['threshold'].append(test_results[label_name]['threshold'])

        for i, item in enumerate(fold_test_data):
            probs = test_preds[i]
            binary_preds = [1 if probs[j] >= best_val_thresholds[j] else 0 for j in range(len(probs))]

            fold_results.append({
                'fold': fold + 1,
                'cve': item['cve'],
                'commit1': item['commit1'],
                'commit2': item['commit2'],
                'true_labels': item['labels'],
                'pred_labels': binary_preds,
                'probs': probs,
                'thresholds': best_val_thresholds
            })

    print("\n===== Dictionary-based Evaluation =====")

    cve_data = defaultdict(lambda: {
        'true': defaultdict(lambda: defaultdict(list)),
        'pred': defaultdict(lambda: defaultdict(list)),
        'true_separate': set(),
        'pred_separate': set()
    })

    for res in fold_results:
        cve = str(res['cve'])
        c1 = str(res['commit1'])
        c2 = str(res['commit2'])
        t_labels = res['true_labels']
        p_labels = res['pred_labels']

        for idx, label_name in enumerate(LABEL_NAMES):
            if label_name == 'separate':
                if t_labels[idx] == 1:
                    cve_data[cve]['true_separate'].add(c1)
                    cve_data[cve]['true_separate'].add(c2)
                if p_labels[idx] == 1:
                    cve_data[cve]['pred_separate'].add(c1)
                    cve_data[cve]['pred_separate'].add(c2)
                continue

            if t_labels[idx] == 1:
                cve_data[cve]['true'][label_name][c1].append(c2)
            if p_labels[idx] == 1:
                cve_data[cve]['pred'][label_name][c1].append(c2)

    eval_rows = []
    all_cves = sorted(cve_data.keys())

    for cve in all_cves:
        row = {'cve': cve}
        data = cve_data[cve]

        row['separate'] = list(data['true_separate'])
        row['ans_separate'] = list(data['pred_separate'])

        for label_name in LABEL_NAMES:
            if label_name == 'separate': continue
            row[label_name] = dict(data['true'][label_name])
            row['ans_' + label_name] = dict(data['pred'][label_name])

        eval_rows.append(row)

    if not eval_rows:
        print("No evaluation data generated.")
        return {}, [], fold_results

    df_eval = pd.DataFrame(eval_rows)
    print(f"Evaluating on {len(df_eval)} CVEs...")

    results = {}
    cols = [l for l in LABEL_NAMES if l != 'separate']
    ans_cols = ['ans_' + col for col in cols]

    for col, ans_col in zip(cols, ans_cols):
        if col in df_eval.columns:
            try:
                true_series = df_eval[col].apply(lambda x: x if isinstance(x, dict) else {})
                pred_series = df_eval[ans_col].apply(lambda x: x if isinstance(x, dict) else {})

                precision, recall, f1, tp, pred, gold, error_cves = evaluate_dict_column(
                    true_series, pred_series, col, df_eval
                )
                print(f"{col}: P={precision:.4f}, R={recall:.4f}, F1={f1:.4f} (TP={tp}, Pred={pred}, Gold={gold})")
                results[col] = {
                    'precision': precision, 'recall': recall, 'f1': f1,
                    'accuracy': 0
                }
            except Exception as e:
                print(f"Error evaluating {col}: {e}")

    if 'separate' in df_eval.columns and 'ans_separate' in df_eval.columns:
        try:
            precision, recall, f1, tp, pred, gold = evaluate_separate_column(
                df_eval['separate'], df_eval['ans_separate']
            )
            print(f"separate: P={precision:.4f}, R={recall:.4f}, F1={f1:.4f} (TP={tp}, Pred={pred}, Gold={gold})")
            results['separate'] = {
                'precision': precision, 'recall': recall, 'f1': f1, 'accuracy': 0
            }
        except Exception as e:
            print(f"Error evaluating separate: {e}")

    print("Generating Detailed Venn Diagram Data...")

    group1_labels = ['mirror', 'merge', 'separate']
    group2_labels = ['collab', 'better', 'fix-of']

    venn_g1_rows = []
    venn_g2_rows = []

    for _, row in df_eval.iterrows():
        cve = row['cve']

        for label in LABEL_NAMES:
            target_list = venn_g1_rows if label in group1_labels else venn_g2_rows

            if label == 'separate':
                t_list = row.get('separate', [])
                p_list = row.get('ans_separate', [])
                t_list = t_list if isinstance(t_list, list) else []
                p_list = p_list if isinstance(p_list, list) else []
                p_set = set(p_list)

                for item in t_list:
                    is_correct = 1 if item in p_set else 0
                    uid = f"{cve}#{label}#{item}"
                    target_list.append({
                        'uid': uid,
                        'cve': cve,
                        'label': label,
                        'item': item,
                        f'{MODEL_NAME}': is_correct
                    })
            else:
                t_dict = row.get(label, {})
                p_dict = row.get('ans_' + label, {})

                t_dict = t_dict if isinstance(t_dict, dict) else {}
                p_dict = p_dict if isinstance(p_dict, dict) else {}

                for c1, c2_list in t_dict.items():
                    if not isinstance(c2_list, list): continue

                    p_c2_list = p_dict.get(c1, []) if isinstance(p_dict, dict) else []

                    t_c2_set = set(c2_list)
                    p_c2_set = set(p_c2_list) if isinstance(p_c2_list, list) else set()

                    is_correct = 1 if t_c2_set == p_c2_set else 0

                    uid = f"{cve}#{label}#{c1}"

                    t_vals_str = ",".join(sorted(list(t_c2_set)))

                    target_list.append({
                        'uid': uid,
                        'cve': cve,
                        'label': label,
                        'item': f"{c1}->[{t_vals_str}]",
                        f'{MODEL_NAME}': is_correct
                    })

    if venn_g1_rows:
        df_g1 = pd.DataFrame(venn_g1_rows)
        df_g1.sort_values(by=['cve', 'uid'], inplace=True)
        g1_path = os.path.join(SAVE_DIR, 'venn_data_group1_details.csv')
        df_g1.to_csv(g1_path, index=False)
        print(f"Group 1 details saved to {g1_path}")

    if venn_g2_rows:
        df_g2 = pd.DataFrame(venn_g2_rows)
        df_g2.sort_values(by=['cve', 'uid'], inplace=True)
        g2_path = os.path.join(SAVE_DIR, 'venn_data_group2_details.csv')
        df_g2.to_csv(g2_path, index=False)
        print(f"Group 2 details saved to {g2_path}")

    avg_thresholds = []
    if fold_results:
        fold_threshold_map = {}
        for res in fold_results:
            fold_id = res['fold']
            if fold_id not in fold_threshold_map:
                fold_threshold_map[fold_id] = res['thresholds']

        if fold_threshold_map:
            sum_thresholds = np.zeros(len(LABEL_NAMES))
            for t in fold_threshold_map.values():
                sum_thresholds += np.array(t)
            avg_thresholds = (sum_thresholds / len(fold_threshold_map)).tolist()
        else:
            avg_thresholds = [0.5] * len(LABEL_NAMES)
    else:
        avg_thresholds = [0.5] * len(LABEL_NAMES)

    np.save(os.path.join(SAVE_DIR, 'avg_thresholds.npy'), avg_thresholds)

    return results, avg_thresholds, fold_results

def predict_relationship(commit1_id, commit2_id, model_path=None, thresholds=None):
    commit_details_df = pd.read_csv('../commit_details.csv')

    c1_short = str(commit1_id).strip()[:7]
    c2_short = str(commit2_id).strip()[:7]

    commit_map = {}
    for _, row in commit_details_df.iterrows():
        cid = row.get('commit_hash', row.get('commit'))
        if pd.notna(cid):
            short_cid = str(cid).strip()[:7]
            commit_map[short_cid] = row

    if c1_short not in commit_map or c2_short not in commit_map:
        print(f"Cannot find commit info for {commit1_id} or {commit2_id}")
        return None

    commit1_info = commit_map[c1_short]
    commit2_info = commit_map[c2_short]

    def build_commit_text(r):
        return (
            f"Commit ID: {r.get('commit','')}\n"
            f"Commit Time: {r.get('commit_time','')}\n"
            f"Branch: {r.get('branch','')}\n"
            f"Version: {r.get('tags','')}\n"
            f"Message: {clean_text(r.get('msg_text', r.get('message','')))}\n"
            f"Code Diff: {clean_text(r.get('diff_code',''))}"
        )

    text1 = build_commit_text(commit1_info)
    text2 = build_commit_text(commit2_info)
    combined_text = text1 + " [SEP] " + text2

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    config = AutoConfig.from_pretrained(MODEL_NAME)
    model = BertForMultiLabelClassification(config, num_labels=len(LABEL_NAMES))
    if model_path is None:
        model_path = os.path.join(SAVE_DIR, 'best_model.pt')
    model.load_state_dict(torch.load(model_path))
    model.to(DEVICE)
    model.eval()
    if thresholds is None:
        try:
            thresholds = np.load(os.path.join(SAVE_DIR, 'avg_thresholds.npy'))
        except:
            thresholds = [0.5] * len(LABEL_NAMES)
    encoding = tokenizer(
        combined_text,
        truncation=True,
        max_length=MAX_LENGTH,
        padding='max_length',
        return_tensors='pt'
    )
    with torch.no_grad():
        input_ids = encoding['input_ids'].to(DEVICE)
        attention_mask = encoding['attention_mask'].to(DEVICE)
        outputs = model(input_ids, attention_mask)
        logits = outputs.logits
        probs = torch.sigmoid(logits).cpu().numpy()[0]
        preds = (probs >= thresholds).astype(int)
    results = {}
    for i, label_name in enumerate(LABEL_NAMES):
        results[label_name] = {
            'probability': float(probs[i]),
            'prediction': bool(preds[i]),
            'threshold': float(thresholds[i])
        }
    return results

def safe_parse_dict(data, row_idx, col_name):
    if isinstance(data, np.ndarray):
        try:
            data = data.tolist()
        except Exception as e:
            print(f"Error converting ndarray to list in row {row_idx}, column {col_name}: {data}, error: {e}")
            return {}

    if not isinstance(data, (pd.Series, list, dict)) and pd.isna(data):
        return {}

    if isinstance(data, dict):
        return data
    if isinstance(data, pd.Series):
        try:
            if data.size == 1:
                data = data.item()
            else:
                data = data.tolist()
        except Exception as e:
            print(f"Error parsing Series in row {row_idx}, column {col_name}: {data}, error: {e}")
            return {}
    if isinstance(data, str):
        try:
            parsed = ast.literal_eval(data)
            if isinstance(parsed, dict):
                return {k: v for k, v in parsed.items() if not (isinstance(v, list) and len(v) == 0)}
            return parsed
        except (ValueError, SyntaxError) as e:
            return {}
    return {}

def safe_parse_list(data, row_idx, col_name):
    if isinstance(data, np.ndarray):
        try:
            return data.tolist()
        except Exception as e:
            print(f"Error converting ndarray to list in row {row_idx}, column {col_name}: {data}, error: {e}")
            return []

    if not isinstance(data, (pd.Series, list, dict)) and pd.isna(data):
        return []

    if isinstance(data, list):
        return data
    if isinstance(data, pd.Series):
        try:
            if data.size == 0:
                return []
            return data.tolist()
        except Exception as e:
            print(f"Error parsing Series in row {row_idx}, column {col_name}: {data}, error: {e}")
            return []
    if isinstance(data, str):
        try:
            return ast.literal_eval(data)
        except (ValueError, SyntaxError) as e:
            return []
    return []

def evaluate_dict_column(true_col, pred_col, col_name, df, cve_col='cve'):
    recall_true = []
    recall_pred = []
    precision_true = []
    precision_pred = []
    error_cves = set()
    r_correct = set()
    p_correct = set()

    for idx, (true_dict, pred_dict) in enumerate(zip(true_col, pred_col)):
        true_dict = safe_parse_dict(true_dict, idx, f"{col_name}_true")
        pred_dict = safe_parse_dict(pred_dict, idx, f"{col_name}_pred")

        for key in true_dict.keys():
            true_values = sorted(safe_parse_list(true_dict.get(key, []), idx, f"{col_name}_true_{key}"))
            pred_values = sorted(safe_parse_list(pred_dict.get(key, []), idx, f"{col_name}_pred_{key}"))
            recall_true.append(1)
            recall_pred.append(1 if true_values == pred_values else 0)
            if true_values != pred_values:
                try:
                    cve = df[cve_col].iloc[idx]
                    error_cves.add(cve)
                except (IndexError, KeyError):
                    pass
            else:
                r_correct.add(df[cve_col].iloc[idx])

        for key in pred_dict.keys():
            true_values = sorted(safe_parse_list(true_dict.get(key, []), idx, f"{col_name}_true_{key}"))
            pred_values = sorted(safe_parse_list(pred_dict.get(key, []), idx, f"{col_name}_pred_{key}"))
            precision_true.append(1 if true_values == pred_values else 0)
            precision_pred.append(1)
            if true_values != pred_values:
                try:
                    cve = df[cve_col].iloc[idx]
                    error_cves.add(cve)
                except (IndexError, KeyError):
                    pass
            else:
                p_correct.add(df[cve_col].iloc[idx])

    precision = precision_score(precision_true, precision_pred, zero_division=0)
    recall = recall_score(recall_true, recall_pred, zero_division=0)
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall > 0 else 0
    tp = sum(precision_true)
    pred = sum(precision_pred)
    gold = sum(recall_true)
    return precision, recall, f1, tp, pred, gold, error_cves

def evaluate_separate_column(true_col, pred_col):
    recall_numerator = 0
    recall_denominator = 0
    precision_numerator = 0
    precision_denominator = 0

    for idx, (true_list, pred_list) in enumerate(zip(true_col, pred_col)):
        true_list = safe_parse_list(true_list, idx, "separate_true")
        pred_list = safe_parse_list(pred_list, idx, "separate_pred")

        true_set = set(true_list)
        pred_set = set(pred_list)
        common = true_set & pred_set

        if true_list:
            recall_denominator += len(true_list)
            recall_numerator += len(common)

        if pred_list:
            precision_denominator += len(pred_list)
            precision_numerator += len(common)

    recall = recall_numerator / recall_denominator if recall_denominator > 0 else 0
    precision = precision_numerator / precision_denominator if precision_denominator > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall > 0 else 0
    tp = precision_numerator
    pred = precision_denominator
    gold = recall_denominator
    return precision, recall, f1, tp, pred, gold

def main():
    print(f"Device: {DEVICE}")
    print(f"BERT: {MODEL_NAME}")
    print(f"Batch size: {BATCH_SIZE}, LR: {LEARNING_RATE}, Epochs: {EPOCHS}")
    avg_metrics, avg_thresholds, fold_results = train_and_evaluate_10fold()
    np.save(os.path.join(SAVE_DIR, 'avg_thresholds.npy'), avg_thresholds)

    best_fold = 1
    best_model_path = os.path.join(SAVE_DIR, f'model_fold_{best_fold}.pt')
    best_model_copy_path = os.path.join(SAVE_DIR, 'best_model.pt')
    if os.path.exists(best_model_path):
        import shutil
        shutil.copy(best_model_path, best_model_copy_path)
        print(f"Model from fold {best_fold} copied to {best_model_copy_path}")

    labels_df = pd.read_csv('../label.csv')
    for i in range(3):
        print(f"\nExample {i+1}:")
        if i < len(labels_df):
            example = labels_df.iloc[i]
            commit1_id = str(example['commit1']).strip()[:7]
            commit2_id = str(example['commit2']).strip()[:7]
            print(f"Predicting relationship between {commit1_id} and {commit2_id}")
            pred_result = predict_relationship(commit1_id, commit2_id, best_model_copy_path, avg_thresholds)
            if pred_result:
                print("Prediction:")
                for label_name, result in pred_result.items():
                    print(f"  {label_name}: {result['prediction']} (prob: {result['probability']:.4f}, th: {result['threshold']:.4f})")
                print("Actual:")
                for j, label_name in enumerate(LABEL_NAMES):
                    print(f"  {label_name}: {bool(example[label_name])}")
        else:
            print("No more examples in label.csv")

if __name__ == "__main__":
    main()
