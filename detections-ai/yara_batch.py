import os
import shutil
from summary_helper import (
    clone_repo, handle_remove_readonly, parse_yara_rules,
    load_previous_summaries, save_summaries, update_gpt_dict,
    check_for_modify, init_environment, generate_summaries
)

def main():
    try:
        repo_dir = os.getcwd() + '\\yara_repo'
        git_url = 'https://github.com/Security-Onion-Solutions/securityonion-yara.git'
        repo = clone_repo(repo_dir, git_url)

        rules_path = os.path.join(repo_dir, 'yara')
        
        msg_dict = parse_yara_rules(rules_path)

        gpt_dict = load_previous_summaries('yara_summaries.yaml')

        shutil.rmtree(repo_dir, onerror=handle_remove_readonly)

        gpt_dict, added_ids = update_gpt_dict(gpt_dict, msg_dict)

        modified_ids = check_for_modify(gpt_dict, msg_dict)

        test_indices = 10 # Set how many rules to generate summaries for (set to len(list(msg_dict.keys())) to generate summaries for all rules)
        batch_size = 10
        test_ids = (added_ids + modified_ids)[:test_indices]

        client = init_environment()

        prompt = "Summarize the following YARA rule in paragraph form, \
            treating each rule independently. Do not reference previous rules in any way - do not say 'Similar to the previous rule'.\
            Exclude any classification details, references to the ID, and deployment information.\
            If a rule is commented out, still summarize it. Provide clear context about specific software or malware mentioned, \
            including what it does. Ensure the summary is concise, avoids redundancy, and uses consistent technical terminology.\
            Do not reference YARA; start the summary with 'This rule detects...'.\
            When talking about a rule, do not mention whether or not it is commented out.\
            Only give me the summary, do not say anything else. Here is the rule:"
        
        gpt_dict = generate_summaries(client, test_ids, batch_size, prompt, msg_dict, gpt_dict, 'yara', added_ids)

        save_summaries('yara_summaries.yaml', gpt_dict)

    except Exception as e:
        print(f'Error: {e}')
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir, onerror=handle_remove_readonly)
        if os.path.isfile('yara_messages.jsonl'):
            os.remove('yara_messages.jsonl')

if __name__ == "__main__":
    main()