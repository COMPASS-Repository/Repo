
import sys

import git
import time
import requests
import os
import random
import pandas as pd
import math
import xgboost as xgb
import lightgbm as lgb
from sklearn.metrics import *
import re
from bs4 import BeautifulSoup, NavigableString, Tag
import json
import logging
from datetime import datetime
from flask import Flask, g, jsonify, make_response, request
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
import numpy as np
from itsdangerous import Serializer
from itsdangerous import BadSignature, SignatureExpired
from passlib.apps import custom_app_context

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
import torch.optim as optim
from torch.autograd import Variable

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

CORS(app, resources=r'/*')

app.config['SECRET_KEY'] = 'hard to guess string'

app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_RECORD_QUERIES'] = True

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:password@localhost:3306/flasktest?charset=utf8mb4"

db.init_app(app)

auth = HTTPBasicAuth()

CSRF_ENABLED = True

app.debug = True

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
}


class Net(nn.Module):
    def __init__(self, num_feature):
        super(Net, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(num_feature, 32),
            nn.Linear(32, 8),
            nn.Linear(8, 2)
        )
        self.soft = nn.Softmax()

    def forward(self, input_):
        s1 = self.model(input_)
        out = self.soft(s1)
        return out


class FocalLoss(nn.Module):
    def __init__(self, class_num, alpha=None, gamma=2, size_average=True):
        super(FocalLoss, self).__init__()
        if alpha is None:
            self.alpha = Variable(torch.ones(class_num, 1))
        else:
            if isinstance(alpha, Variable):
                self.alpha = alpha
            else:
                self.alpha = Variable(alpha)
        self.gamma = gamma
        self.class_num = class_num
        self.size_average = size_average

    def forward(self, inputs, targets):
        N = inputs.size(0)
        C = inputs.size(1)
        P = F.softmax(inputs, dim=1)
        class_mask = inputs.data.new(N, C).fill_(0)
        class_mask = Variable(class_mask)
        ids = targets.view(-1, 1)
        class_mask.scatter_(1, ids.data, 1.)
        if inputs.is_cuda and not self.alpha.is_cuda:
            self.alpha = self.alpha.cuda()
        alpha = self.alpha[ids.data.view(-1)]
        probs = (P * class_mask).sum(1).view(-1, 1)
        log_p = probs.log()
        batch_loss = -alpha * (torch.pow((1 - probs), self.gamma)) * log_p
        if self.size_average:
            loss = batch_loss.mean()
        else:
            loss = batch_loss.sum()
        return loss


class CNNDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(np.array(X), dtype=torch.float)
        self.y = torch.tensor(np.array(y), dtype=torch.long)
        self.len = self.X.shape[0]

    def __len__(self):
        return self.len

    def __getitem__(self, idx):
        data = self.X[idx]
        label = self.y[idx]
        return data, label


def get_repo_name(repoid):
    if (repoid == 1):
        return "FFmpeg"
    elif (repoid == 2):
        return "ImageMagick"
    elif (repoid == 3):
        return "jenkins"
    elif (repoid == 4):
        return "linux"
    elif (repoid == 5):
        return "moodle"
    elif (repoid == 6):
        return "openssl"
    elif (repoid == 7):
        return "php-src"
    elif (repoid == 8):
        return "phpmyadmin"
    elif (repoid == 9):
        return "qemu"
    elif (repoid == 10):
        return "wireshark"


def get_rank(df, sortby, ascending=False):
    gb = df.groupby('cve')
    l = []
    for item1, item2 in gb:
        item2 = item2.reset_index()
        item2 = item2.sort_values(sortby + ['commit_id'], ascending=ascending)
        item2 = item2.reset_index(drop=True).reset_index()
        l.append(item2[['index', 'level_0']])

    df = pd.concat(l)
    df['rank'] = df['level_0'] + 1
    df = df.sort_values(['index'], ascending=True).reset_index(drop=True)
    return df['rank']


def cnnpre(X_test):
    lr = 0.001
    num_workers = 0
    alpha = 10
    batch_size = 10000
    num_epoches = 20
    device = torch.device('cpu')
    criterion = FocalLoss(class_num=2, alpha=torch.tensor([1, 100]))
    test_dataset = CNNDataset(X_test, pd.Series([1] * X_test.shape[0]))
    num_feature = X_test.shape[1]
    model = Net(num_feature).to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    test_dataloader = DataLoader(dataset=test_dataset,
                                 batch_size=batch_size,
                                 shuffle=False,
                                 num_workers=num_workers,
                                 pin_memory=False)

    model.load_state_dict(torch.load("cnn.ckpt", map_location=torch.device('cpu')))
    with torch.no_grad():
        predict = []
        for i, (data, label) in enumerate(test_dataloader):
            data = data.to(device)
            pred = model(data)
            pred = pred.cpu().detach().numpy()
            predict.extend(pred[:, 1])
        predict = np.array(predict)
        return predict


def fusion_voting(result, cols, suffix=''):
    def get_closest(row, columns):
        l = [row[column] for column in columns]
        l.sort()
        if l[1] - l[0] >= l[2] - l[1]:
            return l[1] + l[2]
        else:
            return l[1] + l[0]

    result['closest'] = result.apply(
        lambda row: get_closest(row, cols), axis=1)
    result['sum'] = 0
    for column in cols:
        result['sum'] = result['sum'] + result[column]
    result['last'] = result['sum'] - result['closest']
    result['rank_fusion_voting' +
           suffix] = get_rank(result, ['closest', 'last'], True)
    result.drop(['sum', 'closest', 'last'], axis=1)
    return result


@app.route('/api/CommitPage', methods=['GET'])
def get_gitcommit_list():
    page = request.args.get('page', 1, type=int)
    des = request.args.get('des', 1, type=str)
    repoid = request.args.get('repoid', 0, type=int)
    if (des == ""):
        if (repoid == 0):
            ret = db.session.execute(text(" SELECT sum(commit_num) from repo"))
        else:
            reponame = get_repo_name(repoid)
            ret = db.session.execute(text(" SELECT sum(commit_num) from repo where repo_name=:repo_name"),
                                     {"repo_name": reponame})
    else:
        if (repoid == 0):
            ret = db.session.execute(
                text(" select count(*) from totalcommit where totalcommit.description like :description"),
                {"description": f"%{des}%"})
        else:
            reponame = get_repo_name(repoid)
            ret = db.session.execute(text(
                " select count(*) from totalcommit where repo_name=:repo_name and totalcommit.description like :description"),
                {"repo_name": reponame, "description": f"%{des}%"})
    cds = ret.fetchall()
    L = int(cds[0][0])
    page_size = 20
    print("L:", L)
    if (des == ""):
        if (repoid == 0):
            ret = db.session.execute(text(" select * from totalcommit limit :offset, :limit"),
                                     {"offset": (page - 1) * 20, "limit": 20})
        else:
            reponame = get_repo_name(repoid)
            ret = db.session.execute(
                text(" select * from totalcommit where repo_name=:repo_name limit :offset, :limit"),
                {"repo_name": reponame, "offset": (page - 1) * 20, "limit": 20})
    else:
        if (repoid == 0):
            ret = db.session.execute(text(
                " select * from totalcommit where totalcommit.description like :description limit :offset, :limit"),
                {"description": f"%{des}%", "offset": (page - 1) * 20, "limit": 20})
        else:
            reponame = get_repo_name(repoid)
            ret = db.session.execute(text(
                " select * from totalcommit where repo_name=:repo_name and totalcommit.description like :description limit :offset, :limit"),
                {"repo_name": reponame, "description": f"%{des}%", "offset": (page - 1) * 20,
                 "limit": 20})
    cds = ret.fetchall()
    columns = ["commit_id", "repo_name", "author", "description", "commit_time"]
    list = []
    for u in cds:
        result = {}
        for i in range(5):
            result[columns[i]] = u[i + 1]
        list.append(result)
    return jsonify({
        'code': 200,
        'total': L,
        'page_size': page_size,
        'infos': list
    })


from predict_relation import generate_prompt_file, predict_relations
@app.route('/api/CVEPage', methods=['GET'])
def get_gitCVE_list():
    page = request.args.get('page', 1, type=int)
    cve = request.args.get('CVE', 1, type=str)
    repo = request.args.get('repo', '', type=str)

    page_size = 20

    columns = ["cve", "cve_time", "repo", "patch num", "commit list", "cwe_id", "cwe_type", 'commit', 'desc',
               "merge", "mirror", "better", "fix-of", "collab", "test"]
    generate_prompt_file(cve)
    predict_relations(cve)
    df = pd.read_csv(f'/home/ubuntu/Desktop/tool/cache/{cve}_graph.csv')

    columns = ["cve", "desc", "answer", "merge", "mirror", "better", "fix-of", "collab", "separate"]
    list_data = []
    for _, row in df.iterrows():
        result = {col: row[col] for col in columns}
        list_data.append(result)

    print(list_data)
    return jsonify({
        'code': 200,
        'page_size': page_size,
        'infos': list_data
    })


@app.route('/api/GetCommitPieChart', methods=['GET'])
def getcommitPieChart():
    ret = db.session.execute(text("select repo_name,commit_num from repo"))
    cds = ret.fetchall()
    columns = ["repo_name", "commit_num"]
    total = 0
    list = []
    repo = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        repo.append(u[0])
        total += u[1]
        list.append(result)

    return jsonify({'code': 200, 'value': list, 'total': total, 'repo': repo})


@app.route('/api/GetCVEPieChart', methods=['GET'])
def getCVEPieChart():
    ret = db.session.execute(text("select repo_name,count(*) from cve GROUP BY repo_name"))
    cds = ret.fetchall()
    columns = ["repo_name", "num"]
    total = 0
    list = []
    repo = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        repo.append(u[0])
        total += u[1]
        list.append(result)

    return jsonify({'code': 200, 'value': list, 'total': total, 'repo': repo})


@app.route('/api/GetCVEYearLineChart', methods=['GET'])
def getCVEyearLineChart():
    ret = db.session.execute(text("SELECT left(cvetime,4),count(*) from cve GROUP BY left(cvetime,4)"))
    cds = ret.fetchall()
    total = 0
    list = []
    time = []
    for u in cds:
        list.append(u[1])
        time.append(u[0])
        total += u[1]

    return jsonify({'code': 200, 'value': list, 'total': total, 'time': time})


@app.route('/api/GetCVEWatchChart', methods=['GET'])
def getCVEWatchChart():
    ret = db.session.execute(text("SELECT avg(score),count(*) from cve where score!=0"))
    cds = ret.fetchall()
    for u in cds:
        score = u[0]
        num = u[1]
    score = round(score, 2)
    return jsonify({'code': 200, 'score': score, 'num': num})


@app.route('/api/GetCVECircleChart', methods=['GET'])
def getCVECircleChart():
    ret = db.session.execute(text("""
            SELECT 
                CASE 
                    WHEN `patch num` = 2 THEN '2'
                    WHEN `patch num` = 3 THEN '3'
                    WHEN `patch num` = 4 THEN '4'
                    WHEN `patch num` = 5 THEN '5'
                    WHEN `patch num` = 6 THEN '6'
                    WHEN `patch num` > 6 THEN '6+'
                    ELSE NULL
                END AS patch_num_category,
                COUNT(*) AS count
            FROM multi
            WHERE `patch num` IS NOT NULL
            GROUP BY patch_num_category
            ORDER BY 
                CASE 
                    WHEN patch_num_category = '2' THEN 1
                    WHEN patch_num_category = '3' THEN 2
                    WHEN patch_num_category = '4' THEN 3
                    WHEN patch_num_category = '5' THEN 4
                    WHEN patch_num_category = '6' THEN 5
                    WHEN patch_num_category = '6+' THEN 6
                    ELSE NULL
                END;
        """))
    cds = ret.fetchall()
    columns = ["name", "value"]
    total = 0
    list = []
    name = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        total += u[1]
        name.append(u[0])
        list.append(result)
    return jsonify({'code': 200, 'value': list, 'total': total, 'name': name})


@app.route('/api/GetCVESquareChart', methods=['GET'])
def getCVESquareChart():
    ret = db.session.execute(
        text("select cwe_name,count(*) from cve GROUP BY cwe_name ORDER BY count(*) desc LIMIT 10"))
    cds = ret.fetchall()
    columns = ["name", "value"]
    total = 0
    list = []
    name = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        total += u[1]
        name.append(u[0])
        list.append(result)
    return jsonify({'code': 200, 'value': list, 'total': total, 'name': name})


@app.route('/api/GetNewCVETable', methods=['GET'])
def getNewCVETable():
    ret = db.session.execute(
        text("select CVE_id,repo_name,score,cwe_id,cwe_name,cvetime from cve ORDER BY cvetime desc LIMIT 10"))
    cds = ret.fetchall()
    columns = ["CVE_id", "repo_name", "score", "cwe_id", "cwe_name", "cvetime"]
    list = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        list.append(result)
    return jsonify({'code': 200, 'CVEs': list})


@app.route('/api/GetSingalCVE', methods=['GET'])
def getSingalCVE():
    CVE = request.args.get('CVE', type=str)
    ret = db.session.execute(text(
        " SELECT a.CVE_id,b.Description,a.repo_name,a.cvetime,a.patch_gitcommit,a.score,a.S_des,a.cwe_id,a.cwe_name from cve a,all_cve b where a.`CVE_id`=b.`CVE_id` and a.`CVE_id`=:CVE_id"),
        {"CVE_id": CVE})
    cds = ret.fetchall()
    columns = ["CVE_id", "Description", "repo_name", "cvetime", "patch_gitcommit", "score", "S_des", "cwe_id",
               "cwe_name"]
    list = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        list.append(result)
        c = u[6]
        cve = u[0]
    return jsonify({
        'code': 200,
        'CVEinfos': list[0],
        'color': c,
        'cve': cve
    })


@app.route('/api/Predict', methods=['GET'])
def getPredict():
    cve = request.args.get('CVE', '', type=str)
    repo = request.args.get('Repo', '', type=str)
    print(cve)
    print(repo)
    ret = db.session.execute(text(
        "SELECT commit, commit_time, author, msg_text, branch, tags FROM patch WHERE cve = :cve"),
        {"cve": cve}
    )

    cds = ret.fetchall()

    columns = ["commit", "commit_time", "author", "msg_text", "branch", "tags"]

    list1 = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            col_name = columns[i]
            if col_name in ['branch', 'tags']:
                try:
                    data_list = eval(u[i])
                    result[col_name] = data_list[0] if data_list else None
                except:
                    result[col_name] = None
            else:
                result[col_name] = u[i]
        list1.append(result)

    print(list1)

    ret = db.session.execute(text(
        "SELECT cve, cve_time, repo, `patch num`, `commit list`, cwe_id, cwe_type, `commit`, `desc`,"
                 "`merge`, `mirror`, `better`, `fix-of`, `collab`, `test` "
                 "FROM multi WHERE `cve` = :cve"),{"cve": cve}
    )

    cds2 = ret.fetchall()

    columns2 = ["cve", "cve_time", "repo", "patch num", "commit list", "cwe_id", "cwe_type", 'commit', 'desc',
               "merge", "mirror", "better", "fix-of", "collab", "test"]

    list2 = []
    for u in cds2:
        result = {}
        for i in range(len(columns2)):
            result[columns2[i]] = u[i]
        list2.append(result)

    print(list2)

    return jsonify({
        'infos': list1,
        'info': list2
    })


@app.route('/api/Predict_', methods=['GET'])
def getPredict_():
    print("sosossosososo")
    CVE = request.args.get('CVE', type=str)
    forrank = ['cve', 'commit_id', 'label']
    feature1_cols = ['addcnt', 'delcnt', 'totalcnt', 'issue_cnt', 'web_cnt', 'bug_cnt', 'cve_cnt', 'time_dis',
                     'inter_token_cwe_cnt', 'inter_token_cwe_ratio', 'vuln_commit_tfidf', 'cve_match',
                     'bug_match', 'func_match', 'filepath_match', 'file_match', 'likehood', 'vuln_type_1',
                     'vuln_type2',
                     'vuln_type3', 'mess_shared_ratio', 'mess_max', 'mess_sum', 'mess_mean', 'mess_var',
                     'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var']


    vuln_cols = ['vuln_emb' + str(i) for i in range(32)]
    cmt_cols = ['cmt_emb' + str(i) for i in range(32)]
    columns = forrank + feature1_cols + vuln_cols + cmt_cols
    Col = ", ".join(columns)
    ret = db.session.execute(text("SELECT " + Col + " from vc_feature WHERE cve=:cve"), {"cve": CVE})
    cds = ret.fetchall()
    list = []
    length = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        list.append(result)
        length.append(len(list) - 1)
    test = pd.DataFrame(list, index=length)

    param = {
        'max_depth': 5,
        'eta': 0.05,
        'verbosity': 1,
        'random_state': 2021,
        'objective': 'binary:logistic',
        'tree_method': 'gpu_hist'
    }

    def myFeval(preds, dtrain):
        labels = dtrain.get_label()
        return 'error', math.sqrt(mean_squared_log_error(preds, labels))

    X_test = test[feature1_cols + vuln_cols + cmt_cols]
    print("loadover")
    model1 = xgb.Booster({'nthread': 4})
    model1.load_model('xgb.model')
    result = test[['cve', 'commit_id', 'label']]
    result.loc[:, 'prob_xgb'] = 0
    xgbpredict = model1.predict(xgb.DMatrix(X_test))
    print("xgbover")
    model2 = lgb.Booster(model_file='lgb.model')
    result.loc[:, 'prob_lgb'] = 0
    lgbpredict = model2.predict(X_test)
    print("lgbover")

    cnnpredict = cnnpre(X_test)
    print("cnnover")
    print("yucewanbi")
    result.loc[X_test.index, 'prob_cnn'] = cnnpredict
    result.loc[X_test.index, 'prob_lgb'] = lgbpredict
    result.loc[X_test.index, 'prob_xgb'] = xgbpredict

    result['rank_xgb'] = get_rank(result, ['prob_xgb'])
    result['rank_lgb'] = get_rank(result, ['prob_lgb'])
    result['rank_cnn'] = get_rank(result, ['prob_cnn'])
    print("rank")
    tmp_col2 = ['rank_xgb', 'rank_lgb', 'rank_cnn']
    result = fusion_voting(result, tmp_col2)

    result.sort_values('rank_fusion_voting', inplace=True)
    result = result[:][:20]
    print("rankover")
    list = []
    for row in result.itertuples():
        ret = db.session.execute(text(" select * from totalcommit where commit_id=:commit_id"),
                                 {"commit_id": row[2]})
        cds = ret.fetchall()
        columns = ["commit_id", "repo_name", "author", "description", "commit_time"]
        result = {}
        for i in range(5):
            result[columns[i]] = cds[0][i + 1]
        result["prob"] = row[4]
        result["rank"] = row[13]
        list.append(result)

    return jsonify({
        'code': 200,
        'commitlist': list
    })


@app.route('/api/CheckCommit', methods=['GET'])
def update_CVE_Commit():
    Commit_id = request.args.get('Commit_id', type=str)
    CVE_id = request.args.get('CVE_id', type=str)
    print("ss:" + Commit_id)
    print(CVE_id)
    if Commit_id:
        ret = db.session.execute(
            text("update cve set patch_gitcommit=:patch_gitcommit where CVE_id= :CVE_id"),
            {"patch_gitcommit": Commit_id, "CVE_id": CVE_id})
        print(ret)
        return jsonify({'code': 200, 'msg': "update successful"})
    else:
        return jsonify({'code': 500, 'msg': "Error"})


@app.route('/api/test', methods=['GET'])
def gettest():
    CVE = "CVE-2000-1254"

    forrank = ['cve', 'commit_id', 'label']
    feature1_cols = ['addcnt', 'delcnt', 'totalcnt', 'issue_cnt', 'web_cnt', 'bug_cnt', 'cve_cnt', 'time_dis',
                     'inter_token_cwe_cnt', 'inter_token_cwe_ratio', 'vuln_commit_tfidf', 'cve_match',
                     'bug_match', 'func_match', 'filepath_match', 'file_match', 'likehood', 'vuln_type_1',
                     'vuln_type2',
                     'vuln_type3', 'mess_shared_ratio', 'mess_max', 'mess_sum', 'mess_mean', 'mess_var',
                     'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var']
    vuln_cols = ['vuln_emb' + str(i) for i in range(32)]
    cmt_cols = ['cmt_emb' + str(i) for i in range(32)]
    columns = forrank + feature1_cols + vuln_cols + cmt_cols
    Col = ", ".join(columns)
    ret = db.session.execute(text("SELECT " + Col + " from vc_feature WHERE cve=:cve"), {"cve": CVE})
    cds = ret.fetchall()
    list = []
    length = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        list.append(result)
        length.append(len(list) - 1)
    df = pd.DataFrame(list, index=length)
    print(df)
    return jsonify({
        'code': 200,
        'commitlist': list
    })


@app.route('/api/GetNewCommitTable', methods=['GET'])
def getNewCommitTable():
    ret = db.session.execute(text("select * from totalcommit LIMIT 10"))
    cds = ret.fetchall()
    columns = ["commit_id", "repo_name", "author", "description", "commit_time"]
    list = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i + 1]
        list.append(result)
    return jsonify({'code': 200, 'Commits': list})


@app.route('/api/GetCommitPieChart', methods=['GET'])
def getCommitPieChart():
    ret = db.session.execute(text("select repo_name,commit_num from repo "))
    cds = ret.fetchall()
    columns = ["repo_name", "commit_num"]
    total = 0
    list = []
    repo = []
    for u in cds:
        result = {}
        for i in range(len(columns)):
            result[columns[i]] = u[i]
        repo.append(u[0])
        total += u[1]
        list.append(result)

    return jsonify({'code': 200, 'value': list, 'total': total, 'repo': repo})


@app.route('/api/AddNewCVE', methods=['GET'])
def add_newCVE():
    cve = request.args.get('CVE', 'CVE-2008-5515', type=str)
    repo = request.args.get('Repo', 'apache_tomcat', type=str)
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
    res = requests.get(url)
    data = res.json()
    cvetime = data['vulnerabilities'][0]['cve']['published']
    cvetime = datetime.strptime(cvetime, "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y%m%d")

    print(cvetime)

    page = 'https://nvd.nist.gov/vuln/detail/' + cve
    res = requests.get(url=page, headers=headers)
    try:
        links = []
        all_links = []
        soup = BeautifulSoup(res.text, 'lxml')
        
        tbody = soup.find(attrs={'data-testid': "vuln-hyperlinks-table"}).tbody
        for tr in tbody.children:
            if isinstance(tr, NavigableString): continue
            tds = tr.findAll('td')
            if tds[0].a['href'] not in all_links:
                all_links.append(tds[0].a['href'])
            if len(tds) >= 3 and 'Patch' in tds[2].text:
                link_href = tds[0].a['href']
                if 'commit' in link_href and link_href not in links:
                    links.append(link_href)
        tbody = soup.find(attrs={'data-testid': "vuln-CWEs-table"}).tbody
        for tr in tbody.children:
            if isinstance(tr, NavigableString): continue
            tds = tr.findAll('td')
            cwe_id = tds[0].text
            cwe_id = cwe_id.replace("\n", '')
            cwe_name = tds[1].text

        description_element = soup.find(attrs={'data-testid': "vuln-description"})
        if description_element:
            desc = description_element.text
        else:
            desc = ""

        tbody = soup.find(attrs={'data-testid': "vuln-cvss3-panel-score-na"})
        if tbody is None:
            tbody = soup.find(attrs={'data-testid': "vuln-cvss3-panel-score"})
            if tbody is None:
                tbody = soup.find(attrs={'data-testid': "vuln-cvss3-cna-panel-score"})
                score = tbody.string
            else:
                score = tbody.string
            strlist = score.split(" ")
            score = float(strlist[0])
            S_des = strlist[1]
        else:
            S_des = "NONE"
            score = 0
    except Exception as e:
        logging.info(page + " ")

    db.session.commit()
    cve_to_save = {
        'cve': cve,
        'repo': [repo],
        'cve_time': cvetime,
        'links' : all_links,
        'cwe' : [(cwe_id, cwe_name)],
        'desc': desc,
        'patch num': len(links),
        'cwe_id': cwe_id,
        'cwe_type': cwe_name,
    }
    df = pd.DataFrame([cve_to_save])
    if not os.path.exists('./cache/'):
        os.makedirs('./cache/')
    df.to_csv(f'./cache/{cve}.csv', index = False)

    return jsonify({
        'code': 200,
        'infos': {
            'CVE_id': cve,
            'repo': repo,
            'cvetime': cvetime,
            'cwe_id': cwe_id,
            'cwe_type': cwe_name,
            'patch_links': links,
            'patch_num': len(links),
            'desc': desc
        }
    })


@app.route('/api/addCVE', methods=['GET'])
def add_cve():
    cve = request.args.get('CVE', 'CVE-2008-5515', type=str)
    repo = request.args.get('Repo', 'apache_tomcat', type=str)
    page = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}'
    res = requests.get(url=page, headers=headers)
    cvetime = re.search('<td><b>([0-9]{8})</b></td>', res.text).group(1)
    page = f'https://nvd.nist.gov/vuln/detail/{cve}'
    res = requests.get(url=page, headers=headers)
    soup = BeautifulSoup(res.text, 'html.parser')

    cwe = []
    tbody = soup.find(attrs={'data-testid': "vuln-CWEs-table"}).tbody
    for tr in tbody.children:
        if isinstance(tr, NavigableString):
            continue
        tds = tr.findAll('td')
        cwe.append((tds[0].text.replace('\n', ''), tds[1].text))

    cwe_id = [cwe_item[0] for cwe_item in cwe]
    cwe_type = [cwe_item[1] for cwe_item in cwe]
    print(cvetime, cwe_id, cwe_type)

    return jsonify({
        'code': 200,
        'infos': {
            'cvetime': cvetime,
            'cwe_id': cwe_id,
            'cwe_type': cwe_type
        }
    })


import subprocess


@app.route('/api/addCommit', methods=['GET'])
def add_commit():
    repo = request.args.get('repo', 'apache_tomcat', type=str)
    commitCount = request.args.get('commitCount', 10, type=int)
    startDate = request.args.get('startDate', '2020-01-01', type=str)
    endDate = request.args.get('endDate', '2023-01-01', type=str)

    try:
        begin_time = datetime.strptime(startDate, '%Y-%m-%d')
        end_time = datetime.strptime(endDate, '%Y-%m-%d')
    except ValueError:
        return jsonify({
            'code': 400,
            'message': 'Invalid date format. Please use YYYY-MM-DD format.'
        })

    repo_path = f'D:/py/pythonProject10/patchmatch/gitrepo/{repo}'

    try:
        if not os.path.exists(repo_path):
            try:
                owner, repo_name = repo.split('_', 1)
                repo_url = f"https://github.com/{owner}/{repo_name}.git"
                subprocess.run(['git', 'clone', repo_url, repo_path], check=True)
                print(f"Cloned {repo_url} into {repo_path}")
            except subprocess.CalledProcessError as e:
                print(f"Error cloning {repo_url}: {e}")

        git_repo = git.Repo(repo_path)

        begin_str = begin_time.strftime('%Y-%m-%d %H:%M:%S')
        end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

        cmd = ['git', 'log', f'--after={begin_str}', f'--before={end_str}', '--format=%H', f'--max-count={commitCount}']
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=True)
        commit_hashes = result.stdout.strip().split('\n')
        commit_hashes = [c for c in commit_hashes if c]

        all_commits = []

        for commit_hash in commit_hashes:
            commit = git_repo.commit(commit_hash)

            message = commit.message.encode('utf-8', errors='ignore').decode('utf-8')
            author = commit.author.name.encode('utf-8', errors='ignore').decode('utf-8') if commit.author else 'Unknown'
            commit_time = datetime.fromtimestamp(commit.committed_date)
            formatted_time = commit_time.strftime('%Y-%m-%d')

            branches = []
            tags = []

            version_pattern = r'^v\d+\.\d+'

            for ref in git_repo.references:
                if re.match(version_pattern, (str(ref).split('/')[-1])):
                    tags.append(str(ref).split('/')[-1])
                else:
                    branches.append(str(ref).split('/')[-1])

            commit_data = {
                'commit': commit_hash,
                'author': author,
                'msg_text': message,
                'commit_time': formatted_time,
                'branches': branches[0],
                'tags': max(tags),
            }

            all_commits.append(commit_data)
        return jsonify({
            'code': 200,
            'message': f'Found {len(all_commits)} commits',
            'commits': all_commits
        })

    except Exception as e:
        return jsonify({
            'code': 500,
            'message': f'Error: {str(e)}'
        })

from get_feature import extract_rule_based_feature
from initial_ranking import initial_ranking, NewModel
from deepseek import generate_deepseek_analysis
from interrelationship_feature import get_interrelationship_feature
from predict_relevance_score import predict_relevance_scores
from get_each_commit_feature import group_and_get_commit_feature
from group_ranking import predict_group_ranking
import ast
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')
import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
@app.route('/api/AddNewCommit', methods=['GET'])
def add_newCommit():
    time1 = datetime.now()
    cve = request.args.get('cve', '', type=str)
    repo = request.args.get('repo', '', type=str)
    repo = repo.replace('/', '_')
    repo_path = f'./gitrepo/{repo}'
    commitCount = request.args.get('commitCount', 1500, type=int)
    startDate = request.args.get('startDate', '2018-02-01', type=str)
    endDate = request.args.get('endDate', '2018-02-28', type=str)
    try:
        begin_time = datetime.strptime(startDate, '%Y-%m-%d')
        end_time = datetime.strptime(endDate, '%Y-%m-%d')
    except ValueError:
        return jsonify({
            'code': 400,
            'message': 'Invalid date format. Please use YYYY-MM-DD format.'
        })
    print(f"Fetching commits for {repo} from {begin_time} to {end_time}")
    try:
        pwd = os.getcwd()
        parent = os.path.dirname(pwd)
        gitrepo_dir = os.path.join(parent, 'gitrepo')
        os.makedirs(gitrepo_dir, exist_ok=True)
        
        if not os.path.exists(repo_path):
            try:
                owner, repo_name = repo.split('_', 1)
                repo_url = f"https://github.com/{owner}/{repo_name}.git"
                subprocess.run(['/usr/bin/git', 'clone', repo_url, repo_path], check=True)
                print(f"Cloned {repo_url} into {repo_path}")
            except subprocess.CalledProcessError as e:
                print(f"Error cloning {repo_url}: {e}")
                return jsonify({
                    'code': 500,
                    'message': f'Error cloning repository: {str(e)}'
                })
        git_repo = git.Repo(repo_path)
        begin_str = begin_time.strftime('%Y-%m-%d %H:%M:%S')
        end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

        cmd = ['/usr/bin/git', 'log', f'--after={begin_str}', f'--before={end_str}', '--format=%H', f'--max-count={commitCount}']
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=True)
        commit_hashes = result.stdout.strip().split('\n')
        commit_hashes = [c for c in commit_hashes if c]
        print(f"Found {len(commit_hashes)} commits in the specified date range.")
        all_commits = []
        
        for i, commit_hash in enumerate(tqdm(commit_hashes, desc="Processing commits")):
            commit = git_repo.commit(commit_hash)

            message = commit.message.encode('utf-8', errors='ignore').decode('utf-8')
            author = commit.author.name.encode('utf-8', errors='ignore').decode('utf-8') if commit.author else 'Unknown'
            committer = commit.committer.name.encode('utf-8', errors='ignore').decode('utf-8') if commit.committer else 'Unknown'
            commit_time = datetime.fromtimestamp(commit.committed_date)
            if len(commit.parents) > 0:
                diff_code = git_repo.git.diff(f"{commit_hash}~1", commit_hash, ignore_blank_lines=True, ignore_space_at_eol=True)
            else:
                diff_code = git_repo.git.show(commit_hash, format='', ignore_blank_lines=True, ignore_space_at_eol=True)
             

            sign_pattern = r'(?i)^\s*(Signed[-\s]off[-\s]by|Submitted[-\s]by|Reviewed[-\s]by|Reported-and-tested-by|Cc|Acked[-\s]by|Reported[-\s]by|Tested[-\s]by|Suggested[-\s]by|Co-developed-by):\s*([A-Za-z\s]+)\s*<'
            sign_name_matches = re.findall(sign_pattern, message, flags=re.MULTILINE)
            sign_name = [name.strip() for _, name in sign_name_matches]
            sign_name = list(set(sign_name))
            sign_line_pattern = r'(?i)^\s*(Signed[-\s]off[-\s]by|Submitted[-\s]by|Reviewed[-\s]by|Reported-and-tested-by|Cc|Acked[-\s]by|Reported[-\s]by|Tested[-\s]by|Suggested[-\s]by|Co-developed-by):.*'
            message = re.sub(sign_line_pattern, '', message, flags=re.MULTILINE)
            url_pattern = r'https?://[a-zA-Z0-9-._~:/?#[\]@!$&\'()*+,;%=]+'
            urls = re.findall(url_pattern, message)
            urls = list(set(urls))
            message = re.sub(url_pattern, '', message)
            message = message.replace('\r\n', ' ').replace('\n', ' ')
            if len(diff_code.split('\n')) > 1000:
                diff_code = '\n'.join(diff_code.split('\n')[:1000])
            diff_code = diff_code.encode('utf-8', errors='ignore').decode('utf-8')
            if diff_code == '':
                diff_code = ' '
            commit_data = {
                'cve' : cve,
                'repo' : repo,
                'commit': commit_hash,
                'msg_text': message,
                'msg_url': urls,
                'msg_sign': sign_name,
                'diff_code': diff_code,
                'commit_time': commit_time,
                'author': author,
                'committer': committer,
            }
            all_commits.append(commit_data)
        print(f"Processed {len(all_commits)} commits.")
        df = pd.DataFrame(all_commits)
        df.to_csv(f'./cache/{cve}_commits.csv', index=False)

        try:
            if not os.path.exists(f'./cache/{cve}_group_ranking_results.csv'):
                extract_rule_based_feature(cve)
                initial_ranking(cve)
                generate_deepseek_analysis(cve)
                get_interrelationship_feature(cve)
                predict_relevance_scores(cve)
                group_and_get_commit_feature(cve)
                top_commits = predict_group_ranking(cve)
            else:
                print(f"Group ranking results for {cve} already exist. Skipping feature extraction and ranking.")
                df_ranking = pd.read_csv(f'./cache/{cve}_group_ranking_results.csv')

                ranking_row = df_ranking.loc[df_ranking['rank'] == 1]
                if not ranking_row.empty:
                    top_commits = ranking_row['commit'].iloc[0]
                else:
                    top_commits = df_ranking['commit'].iloc[0] if not df_ranking.empty else "[]"
        except Exception as e:
            print(f"Error during feature extraction or ranking: {e}")
            return jsonify({
                'code': 500,
                'message': f'Error during feature extraction or ranking: {str(e)}'
            })
        print(f"Top commits for {cve}: {top_commits}")
        if isinstance(top_commits, str):
            top_commits = ast.literal_eval(top_commits)
        final_commits = []
        for commit_hash in top_commits:
            commit = git_repo.commit(commit_hash)

            message = commit.message.encode('utf-8', errors='ignore').decode('utf-8')
            author = commit.author.name.encode('utf-8', errors='ignore').decode('utf-8') if commit.author else 'Unknown'
            committer = commit.committer.name.encode('utf-8', errors='ignore').decode('utf-8') if commit.committer else 'Unknown'
            commit_time = datetime.fromtimestamp(commit.committed_date)
            formatted_time = commit_time.strftime('%Y-%m-%d')
            branches = []
            try:
                branch_cmd = ['/usr/bin/git', 'branch', '--contains', commit_hash, '--all']
                branch_result = subprocess.run(branch_cmd, cwd=repo_path, capture_output=True, text=True)
                if branch_result.returncode == 0:
                    branch_lines = branch_result.stdout.strip().split('\n')
                    for line in branch_lines:
                        line = line.strip()
                        if line and not line.startswith('*'):
                            if line.startswith('remotes/origin/'):
                                branch_name = line.replace('remotes/origin/', '')
                                if branch_name != 'HEAD':
                                    branches.append(branch_name)
                            elif not line.startswith('remotes/'):
                                branches.append(line)
                    branches = list(set(branches))
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                print(f"Warning: Could not get branch info for commit {commit_hash}: {e}")
                branches = ['unknown']
            
            tags = []
            try:
                tag_cmd = ['/usr/bin/git', 'tag', '--contains', commit_hash]
                tag_result = subprocess.run(tag_cmd, cwd=repo_path, capture_output=True, text=True)
                if tag_result.returncode == 0:
                    tag_lines = tag_result.stdout.strip().split('\n')
                    for line in tag_lines:
                        line = line.strip()
                        if line:
                            tags.append(line)
                    tags = tags
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                print(f"Warning: Could not get tag info for commit {commit_hash}: {e}")
                tags = ['unknown']
            
            commit_data = {
                'commit': commit_hash,
                'author': author,
                'msg_text': message,
                'commit_time': formatted_time,
                'branches': branches[0],
                'tags': tags[0],
            }
            final_commits.append(commit_data)

        df = pd.DataFrame(final_commits)
        df2 = pd.read_csv(f'./cache/{cve}_commits.csv')
        df = df.merge(df2[['commit', 'diff_code', 'cve']], on='commit', how='left')
        df.to_csv(f'./cache/{cve}_final.csv', index=False)

        time2 = datetime.now()
        print(f"Total processing time: {time2 - time1}")
        return jsonify({
            'code': 200,
            'infos': final_commits,
        })
        
    except Exception as e:
        print(f"Error processing request: {e}")
        
        return jsonify({
            'code': 500,
            'message': f'Error: {str(e)}'
        })


def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
