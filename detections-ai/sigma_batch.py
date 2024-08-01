import os
import shutil
from summary_helper import (
    download_rules, clone_repo, handle_remove_readonly,
    parse_sigma_rules, load_previous_summaries, save_summaries,
    update_gpt_dict, check_for_modify, init_environment, generate_summaries
)

def main():
    try:
        so_dir = os.getcwd() + '\\sigma_so'
        so_url = 'https://github.com/Security-Onion-Solutions/securityonion-resources.git'
        repo = clone_repo(so_dir, so_url)

        so_path = os.path.join(so_dir, 'sigma', 'stable')

        core_dir = os.getcwd() + '\\sigma_core'
        core_url = 'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip'
        download_rules(core_url, extract_to=core_dir)

        core_path = os.path.join(core_dir, 'rules')

        et_dir = os.getcwd() + '\\sigma_et'
        et_url = 'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_emerging_threats_addon.zip'
        download_rules(et_url, extract_to=et_dir)

        et_path = os.path.join(et_dir, 'rules-emerging-threats')
        
        msg_dict, ruleset_dict = parse_sigma_rules(so_path, core_path, et_path)
        
        gpt_dict = load_previous_summaries('sigma_summaries.yaml')

        shutil.rmtree(so_dir, onerror=handle_remove_readonly)
        shutil.rmtree(core_dir, onerror=handle_remove_readonly)
        shutil.rmtree(et_dir, onerror=handle_remove_readonly)

        gpt_dict, added_ids = update_gpt_dict(gpt_dict, msg_dict)

        modified_ids = check_for_modify(gpt_dict, msg_dict)

        test_indices = 120 # Set how many rules to generate summaries for (set to len(list(msg_dict.keys())) to generate summaries for all rules)
        batch_size = 70
        test_ids = (added_ids + modified_ids)[:test_indices]

        client = init_environment()

        prompt = "Summarize the following Sigma rule in paragraph form, \
            treating each rule independently. Do not reference previous rules in any way - do not say 'Similar to the previous rule'.\
            Exclude any classification details and deployment information.\
            If a rule is commented out, still summarize it. Provide clear context about specific software or malware mentioned, \
            including what it does. Ensure the summary is concise, avoids redundancy, and uses consistent technical terminology.\
            Do not reference Sigma; start the summary with 'This rule detects...'.\
            When talking about a rule, do not mention whether or not it is commented out.\
            Only give me the summary, do not say anything else. Here is the rule:"

        gpt_dict = generate_summaries(client, test_ids, batch_size, prompt, msg_dict, gpt_dict, 'sigma', added_ids, ruleset_dict=ruleset_dict)

        save_summaries('sigma_summaries.yaml', gpt_dict)

    except Exception as e:
        print(f'Error: {e}')
        if os.path.exists(so_dir):
            shutil.rmtree(so_dir, onerror=handle_remove_readonly)
        if os.path.exists(core_dir):
            shutil.rmtree(core_dir, onerror=handle_remove_readonly)
        if os.path.exists(et_dir):
            shutil.rmtree(et_dir, onerror=handle_remove_readonly)
        if os.path.isfile('sigma_messages.jsonl'):
            os.remove('sigma_messages.jsonl')

if __name__ == "__main__":
    main()