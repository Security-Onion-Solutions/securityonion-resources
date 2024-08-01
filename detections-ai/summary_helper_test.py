import pytest
import os
import yaml
import json
from io import BytesIO
from zipfile import ZipFile
import hashlib
from summary_helper import (
    handle_remove_readonly, clone_repo, fetch_rules, download_rules,
    parse_suricata_rules, parse_yara_rules, parse_sigma_rules,
    load_previous_summaries, save_summaries, save_jsonl,
    update_gpt_dict, check_for_modify, init_environment, generate_summaries
)

@pytest.fixture
def mock_git_repo(mocker):
    return mocker.patch('git.Repo.clone_from', autospec=True)

@pytest.fixture
def mock_shutil_rmtree(mocker):
    return mocker.patch('shutil.rmtree', autospec=True)

@pytest.fixture
def mock_response_text():
    return """
alert tcp any any -> any any (msg:"ET POLICY Dropbox Client Advertising"; sid:2028186;)
alert tcp any any -> any any (msg:"ET POLICY Dropbox Client Sync"; sid:2028187;)
"""

@pytest.fixture
def mock_yaml_content():
    return """
rule TestRule {
    meta:
        id = "test_id"
        description = "Test rule"
    strings:
        $a = "test"
    condition:
        $a
}
"""

@pytest.fixture
def mock_sigma_rule_yaml():
    return """
id: "test_sigma_rule"
title: "Test Sigma Rule"
description: "This is a test sigma rule."
"""

@pytest.fixture
def mock_gpt_dict():
    return {
        "test_id": {
            "Ruleset": "core",
            "Created-Date": "2024_07_29",
            "Updated-Date": "2024_07_29",
            "Summary": "Test summary",
            "Rule-Body-Hash": "mock_hash",
            "Custom-Edited": False
        }
    }

@pytest.fixture
def mock_zip_file():
    file_content = b'This is a test file.'
    file_like_object = BytesIO()
    with ZipFile(file_like_object, 'w') as zip_file:
        zip_file.writestr('test_file.txt', file_content)
    file_like_object.seek(0)
    return file_like_object

@pytest.fixture
def mock_openai(mocker):
    return mocker.patch('summary_helper.OpenAI', autospec=True)

def test_init_environment(mock_openai):
    mock_openai_instance = mock_openai.return_value
    mock_openai_instance.api_key = 'mock_api_key'
    
    client = init_environment()

    mock_openai.assert_called_once()
    assert client.api_key == os.environ['OPENAI_API_KEY']

def test_clone_repo(mock_git_repo, mock_shutil_rmtree):
    repo_dir = os.getcwd() + '\\repo_dir'
    git_url = 'https://github.com/mock/repo.git'

    if not os.path.exists(repo_dir):
        os.mkdir(repo_dir)

    clone_repo(repo_dir, git_url)
    mock_shutil_rmtree.assert_called_once_with(repo_dir, onerror=handle_remove_readonly)
    mock_git_repo.assert_called_once_with(git_url, repo_dir)

    if os.path.exists(repo_dir):
        os.rmdir(repo_dir)

def test_handle_remove_readonly(tmpdir):
    test_file = tmpdir.join("test.txt")
    test_file.write("content")
    os.chmod(test_file, 0o444)
    handle_remove_readonly(os.remove, str(test_file), (None, FileNotFoundError(13, "Permission denied")))
    assert not os.path.exists(test_file)

def test_fetch_rules(requests_mock):
    url = "https://example.com/rules"
    requests_mock.get(url, text="rule content")
    content = fetch_rules(url)
    assert content == "rule content"

def test_download_rules(requests_mock, mock_zip_file, tmpdir):
    url = "https://example.com/rules.zip"
    requests_mock.get(url, content=mock_zip_file.read())
    download_rules(url, str(tmpdir))
    assert os.path.exists(tmpdir.join("test_file.txt"))

def test_parse_suricata_rules(mock_response_text):
    msg_dict = parse_suricata_rules(mock_response_text)
    assert msg_dict["2028186"] == 'alert tcp any any -> any any (msg:"ET POLICY Dropbox Client Advertising"; sid:2028186;)'
    assert msg_dict["2028187"] == 'alert tcp any any -> any any (msg:"ET POLICY Dropbox Client Sync"; sid:2028187;)'

def test_parse_yara_rules(tmpdir, mock_yaml_content):
    rule_file = tmpdir.join("test_rule.yara")
    rule_file.write(mock_yaml_content)
    msg_dict = parse_yara_rules(str(tmpdir))
    assert "TestRule" in msg_dict

def test_parse_sigma_rules(tmpdir, mock_sigma_rule_yaml):
    sigma_dir = tmpdir.mkdir("sigma")
    rule_file = sigma_dir.join("test_rule.yml")
    rule_file.write(mock_sigma_rule_yaml)
    msg_dict, ruleset_dict = parse_sigma_rules(str(sigma_dir), str(sigma_dir), str(sigma_dir))
    assert "test_sigma_rule" in msg_dict

def test_load_previous_summaries(tmpdir, mock_gpt_dict):
    summary_file = tmpdir.join("summaries.yml")
    with open(summary_file, 'w') as f:
        yaml.dump(mock_gpt_dict, f)
    summaries = load_previous_summaries(str(summary_file))
    assert summaries == mock_gpt_dict

def test_save_summaries(tmpdir, mock_gpt_dict):
    summary_file = tmpdir.join("summaries.yml")
    save_summaries(str(summary_file), mock_gpt_dict)
    with open(summary_file) as f:
        summaries = yaml.safe_load(f)
    assert summaries == mock_gpt_dict

def test_save_jsonl(tmpdir, mock_gpt_dict):
    jsonl_file = tmpdir.join("summaries.jsonl")
    save_jsonl(str(jsonl_file), mock_gpt_dict.items())
    with open(jsonl_file) as f:
        lines = f.readlines()
    assert len(lines) == len(mock_gpt_dict)

def test_update_gpt_dict(mock_gpt_dict):
    msg_dict = {"new_id": "new_rule"}
    updated_gpt_dict, added_ids = update_gpt_dict(mock_gpt_dict, msg_dict)
    assert "test_id" not in updated_gpt_dict
    assert "new_id" in added_ids

def test_check_for_modify(mock_gpt_dict):
    msg_dict = {"test_id": "This is a test rule"}
    modified_ids = check_for_modify(mock_gpt_dict, msg_dict)
    assert "test_id" in modified_ids

def test_generate_summaries(mocker, mock_gpt_dict):
    client = mocker.Mock()
    test_ids = ["test_id"]
    prompt = "Generate a summary"
    msg_dict = {"test_id": "This is a test rule"}
    engine = "engine"
    batch_size = 1
    ruleset_dict = {"test_id": "core"}
    added_ids = ["test_id"]

    mock_response = [
        {
            'custom_id': 'test_id',
            'response': {
                'body': {
                    'choices': [
                        {
                            'message': {
                                'content': 'This is a test summary'
                            }
                        }
                    ]
                }
            }
        }
    ]

    mock_file_response = mocker.Mock()
    mock_file_response.text = '\n'.join([json.dumps(resp) for resp in mock_response])

    mocker.patch.object(client.files, 'create', return_value=mocker.Mock(id='mock_id'))
    mocker.patch.object(client.batches, 'create', return_value=mocker.Mock(id='batch_id', status='completed'))
    mocker.patch.object(client.batches, 'retrieve', side_effect=[
        mocker.Mock(status='processing', id='batch_id'),
        mocker.Mock(status='completed', output_file_id='output_file_id')
    ])
    mocker.patch.object(client.files, 'content', return_value=mock_file_response)

    gpt_dict = generate_summaries(client, test_ids, batch_size, prompt, msg_dict, mock_gpt_dict, engine, added_ids, ruleset_dict)
    assert "test_id" in gpt_dict
    assert gpt_dict["test_id"]["Summary"] == "This is a test summary"
    assert gpt_dict["test_id"]["Rule-Body-Hash"] == hashlib.md5(msg_dict["test_id"].encode('utf-8')).hexdigest()

if __name__ == "__main__":
    pytest.main()