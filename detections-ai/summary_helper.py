import requests
import re
from openai import OpenAI
import os
import time
import yaml
import json
from datetime import datetime
from git import Repo
import shutil
import stat
import errno
from zipfile import ZipFile
from io import BytesIO
import hashlib

rulesets = {
    'suricata': 'ETOPEN',
    'yara': 'securityonion-yara',
    'sigma': 'core'
}

def handle_remove_readonly(func, path, exc):
    excvalue = exc[1]
    if func in (os.rmdir, os.remove, os.unlink) and excvalue.errno == errno.EACCES:
        os.chmod(path, stat.S_IRWXU)
        func(path)
    else:
        raise

def clone_repo(repo_dir, git_url):
    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir, onerror=handle_remove_readonly)

    return Repo.clone_from(git_url, repo_dir)

def fetch_rules(url):
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to fetch rules")
    return response.text

def download_rules(url, extract_to='.'):
    response = requests.get(url)
    with ZipFile(BytesIO(response.content)) as zip_file:
        zip_file.extractall(extract_to)

def parse_suricata_rules(response_text):
    #get rule bodies
    bodies = re.findall('(?<=\n).*?sid:.*?;\)', response_text)
    
    #dict mapping sid to respective body
    msg_dict = {re.findall('\\bsid: ?[\'"]?(.*?)[\'"]?;', body)[0]: body for body in bodies}
    return msg_dict

def parse_yara_rules(rules_path):
    msg_dict = {}
    for filename in os.listdir(rules_path):
        with open(os.path.join(rules_path, filename)) as readfile:
            content = readfile.read()
            names = re.findall('rule\s+(\S+)\s+\{', content)
            for name in names:
                msg_dict[name] = re.findall('(?s)rule\s+' + name + '\s*\{.*?condition\s*:\s*[^}]*?\}', content)[0]
    return msg_dict

def parse_sigma_rules(so_path, core_path, et_path):
    msg_dict = {}
    ruleset_dict = {}
    for root, _, files in os.walk(so_path):
        for filename in files:
            with open(os.path.join(root, filename), encoding="utf8") as readfile:
                content = readfile.read()
                sigma_rule = yaml.safe_load(content)
                print(sigma_rule)
                id = sigma_rule.get('id', None)
                print(readfile.read())
                msg_dict[id] = content
                ruleset_dict[id] = 'securityonion-resources'
    for root, _, files in os.walk(core_path):
        for filename in files:
            with open(os.path.join(root, filename), encoding="utf8") as readfile:
                content = readfile.read()
                sigma_rule = yaml.safe_load(content)
                print(sigma_rule)
                id = sigma_rule.get('id', None)
                msg_dict[id] = content
                ruleset_dict[id] = 'core'
    for root, _, files in os.walk(et_path):
        for filename in files:
            with open(os.path.join(root, filename), encoding="utf8") as readfile:
                content = readfile.read()
                sigma_rule = yaml.safe_load(content)
                print(sigma_rule)
                id = sigma_rule.get('id', None)
                msg_dict[id] = content
                ruleset_dict[id] = 'emerging-threats'
    return msg_dict, ruleset_dict

def load_previous_summaries(file_path):
    try:
        with open(file_path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}

def save_summaries(file_path, summaries):
    with open(file_path, 'w') as outfile:
        yaml.dump(summaries, outfile)

def save_jsonl(file_path, input):
    with open(file_path, 'w') as outfile:
        for item in input:
            json_line = json.dumps(item)
            outfile.write(json_line + '\n')

def update_gpt_dict(gpt_dict, msg_dict):
    prev_ids = set(gpt_dict.keys())
    curr_ids = set(msg_dict.keys())
    added_ids = list(curr_ids - prev_ids)
    deleted_ids = list(prev_ids - curr_ids)
    
    for id in deleted_ids:
        del gpt_dict[id]

    return gpt_dict, added_ids

def check_for_modify(gpt_dict, msg_dict):
    modified_ids = [id for id in gpt_dict.keys() if gpt_dict[id]['Rule-Body-Hash'] != hashlib.md5(msg_dict[id].encode('utf-8')).hexdigest() and not gpt_dict[id]['Custom-Edited']]
    return modified_ids

def init_environment():
    client = OpenAI()
    client.api_key = os.environ['OPENAI_API_KEY']
    return client

def generate_summaries(client, test_ids, batch_size, prompt, msg_dict, gpt_dict, engine, added_ids, ruleset_dict=None):
    
    for i in range(0, len(test_ids), batch_size):
            
        batch_ids = test_ids[i:i+batch_size]

        jsonl_input = [{"custom_id": batch_ids[j], "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4o", "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}, {"role":"user", "content": msg_dict[batch_ids[j]]}]}} for j in range(len(batch_ids))]

        save_jsonl(f'{engine}_messages.jsonl', jsonl_input)

        with open(f'{engine}_messages.jsonl', 'rb') as f:
            batch_input_file = client.files.create(
                file=f,
                purpose="batch"
            )

        batch_input_file_id = batch_input_file.id

        batch = client.batches.create(
            input_file_id=batch_input_file_id,
            endpoint="/v1/chat/completions",
            completion_window="24h",
            metadata={
                "description": f"testing {engine}"
            }
        )

        while batch.status != 'completed':
            time.sleep(10)
            batch = client.batches.retrieve(batch.id)

        output = client.batches.retrieve(batch.id)
        response = client.files.content(output.output_file_id).text
        response = [json.loads(line) for line in response.splitlines()]

        resp_dict = {dct['custom_id']: dct['response']['body']['choices'][0]['message']['content'] for dct in response}

        print(response)
        print(len(response))

        for id in batch_ids:
            encoded_rule_body = msg_dict[id].encode('utf-8')
            rule_body_hash = hashlib.md5(encoded_rule_body).hexdigest()
            if id in added_ids:
                gpt_dict[id] = {
                    'Ruleset': rulesets[engine] if not ruleset_dict else ruleset_dict[id], 
                    'Created-Date': datetime.now().strftime("%Y_%m_%d"),
                    'Updated-Date': datetime.now().strftime("%Y_%m_%d"),
                    'Summary': resp_dict[id].strip(),
                    'Rule-Body-Hash': rule_body_hash,
                    'Reviewed': False,
                    'Custom-Edited': False
                }
            else:
                gpt_dict[id]['Updated-Date'] = datetime.now().strftime("%Y_%m_%d")
                gpt_dict[id]['Summary'] = resp_dict[id].strip()
                gpt_dict[id]['Rule-Body-Hash'] = rule_body_hash
                gpt_dict[id]['Reviewed'] = False

    if os.path.isfile(f"{engine}_messages.jsonl"):
        os.remove(f"{engine}_messages.jsonl")

    return gpt_dict