import os
from summary_helper import (
    fetch_rules, parse_suricata_rules, load_previous_summaries,
    save_summaries, update_gpt_dict, check_for_modify,
    init_environment, generate_summaries
)

def main():
    try:
        url = 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules'
        response_text = fetch_rules(url)
        
        msg_dict = parse_suricata_rules(response_text)
        
        gpt_dict = load_previous_summaries('suricata_summaries.yaml')

        gpt_dict, added_ids = update_gpt_dict(gpt_dict, msg_dict)

        modified_ids = check_for_modify(gpt_dict, msg_dict)

        test_indices = 20 # Set how many rules to generate summaries for (set to len(list(msg_dict.keys())) to generate summaries for all rules)
        batch_size = 20
        test_ids = (added_ids + modified_ids)[:test_indices]

        client = init_environment()

        prompt = "Summarize the following Suricata rule in paragraph form, \
            treating each rule independently. Do not reference previous rules in any way - do not say 'Similar to the previous rule'.\
            Exclude any classification details, references to the SID, and deployment information.\
            If a rule is commented out, still summarize it. Provide clear context about specific software or malware mentioned, \
            including what it does. Ensure the summary is concise, avoids redundancy, and uses consistent technical terminology.\
            Do not reference Suricata; start the summary with 'This rule detects...'.\
            When talking about a rule, do not mention whether or not it is commented out.\
            Only give me the summary, do not say anything else. Here is the rule:"

        gpt_dict = generate_summaries(client, test_ids, batch_size, prompt, msg_dict, gpt_dict, 'suricata', added_ids)

        save_summaries('suricata_summaries.yaml', gpt_dict)

    except Exception as e:
        print(f'Error: {e}')
        if os.path.isfile('suricata_messages.jsonl'):
            os.remove('suricata_messages.jsonl')

if __name__ == "__main__":
    main()
