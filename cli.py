import argparse
import common
import logging

def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Synchronize code scanning alerts to JIRA ')

    parser.add_argument('--gh_api_url', type=str, nargs='1',
                        help='GitHub api url')
    parser.add_argument('--gh_username', type=str, nargs='1',
                        help='GitHub Username')
    parser.add_argument('--gh_token', type=str, nargs='1',
                        help='GitHub Token')

    parser.add_argument('--jira_url', type=str, nargs='1',
                        help='JIRA url')
    parser.add_argument('--jira_username', type=str, nargs='1',
                        help='JIRA username')
    parser.add_argument('--jira_password', type=str, nargs='1',
                        help='JIRA password')

    
    parser.add_argument('--jira_project', type=str, nargs='1',
                        help='JIRA project')
    parser.add_argument('--gh_repo', type=str, nargs='1',
                        help='GitHub repo')
    
    args = parser.parse_args()

    issues = common.Issues(args.jira_url, (args.jira_username, args.jira_password), args.gh_api_url, (args.gh_username, args.gh_token))
    issues.sync_repo(args.gh_repo, args.jira_project)


if __name__ == "__main__":
    main()