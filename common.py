import os

import requests
from requests import HTTPError
import json
import hashlib
import hmac
import logging
from jira import JIRA
import itertools
import re
from datetime import datetime
from types import SimpleNamespace

# May need to be changed depending on JIRA project type
JIRA_CLOSE_TRANSITION = "Done"
JIRA_REOPEN_TRANSITION = "To Do"
JIRA_OPEN_STATUS = "To Do"
JIRA_CLOSED_STATUS = "Done"

# JIRA Webhook events
JIRA_DELETE_EVENT = 'jira:issue_deleted'
JIRA_UPDATE_EVENT = 'jira:issue_updated'

REQUEST_TIMEOUT = 10
REPO_SYNC_INTERVAL = 60 * 60 * 24     # full sync once a day

JIRA_DESC_TEMPLATE="""
{rule_desc}

{alert_url}

----
This issue was automatically generated from a GitHub alert, and will be automatically resolved once the underlying problem is fixed.
DO NOT MODIFY DESCRIPTION BELOW LINE.
REPOSITORY_NAME={repo_name}
ALERT_NUMBER={alert_num}
REPOSITORY_KEY={repo_key}
ALERT_KEY={alert_key}
"""

class Issues:

    def __init__(self, jira_url, jira_auth, gh_url, gh_auth):
        self.jira = JIRA(jira_url, auth=jira_auth)
        self.gh_url
        self.gh_auth

    def get_alerts(self, repo_id, state = None):
        if state:
            state = '&state=' + state
        else:
            state = ''

        for page in itertools.count(start=1):
            headers = {'Accept': 'application/vnd.github.v3+json'}
            resp = requests.get('{api_url}/repos/{repo_id}/code-scanning/alerts?per_page=100&page={page}{state}'.format(
                                    api_url=self.gh_url,
                                    repo_id=repo_id,
                                    page=page,
                                    state=state
                                ),
                                headers=headers,
                                auth=self.gh_auth,
                                timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            if not resp.json():
                break

            for a in resp.json():
                yield a


    def get_alert(self, repo_id, alert_num):
        headers = {'Accept': 'application/vnd.github.v3+json'}
        resp = requests.get('{api_url}/repos/{repo_id}/code-scanning/alerts/{alert_num}'.format(
                                api_url=self.gh_url,
                                repo_id=repo_id,
                                alert_num=alert_num
                            ),
                            headers=headers,
                            auth=self.gh_auth,
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()


    def open_alert(self, repo_id, alert_num):
        state = self.get_alert(repo_id, alert_num)['state']
        if state != 'open':
            logging.info('Reopen alert {alert_num} of repository "{repo_id}".'.format(alert_num=alert_num, repo_id=repo_id))
            self.update_alert(repo_id, alert_num, 'open')


    def close_alert(self, repo_id, alert_num):
        state = self.get_alert(repo_id, alert_num)['state']
        if state != 'dismissed':
            logging.info('Closing alert {alert_num} of repository "{repo_id}".'.format(alert_num=alert_num, repo_id=repo_id))
            self.update_alert(repo_id, alert_num, 'dismissed')


    def update_alert(self, repo_id, alert_num, state):
        headers = {'Accept': 'application/vnd.github.v3+json'}
        reason = ''
        if state == 'dismissed':
            reason = ', "dismissed_reason": "won\'t fix"'
        data = '{{"state": "{state}"{reason}}}'.format(state=state, reason=reason)
        resp = requests.patch('{api_url}/repos/{repo_id}/code-scanning/alerts/{alert_num}'.format(
                                api_url=self.gh_url,
                                repo_id=repo_id,
                                alert_num=alert_num
                            ),
                            data=data,
                            headers=headers,
                            auth=self.gh_auth,
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()


    def is_managed(self, issue):
        if self.parse_alert_info(issue.fields.description)[0] is None:
            return False
        return True


    def parse_alert_info(self, desc):
        '''
        Parse all the fieldsin an issue's description and return
        them as a tuple. If parsing fails for one of the fields,
        return a tuple of None's.
        '''
        failed = None, None, None, None
        m = re.search('REPOSITORY_NAME=(.*)$', desc, re.MULTILINE)
        if m is None:
            return failed
        repo_id = m.group(1)
        m = re.search('ALERT_NUMBER=(.*)$', desc, re.MULTILINE)
        if m is None:
            return failed
        alert_num = m.group(1)
        m = re.search('REPOSITORY_KEY=(.*)$', desc, re.MULTILINE)
        if m is None:
            return failed
        repo_key = m.group(1)
        m = re.search('ALERT_KEY=(.*)$', desc, re.MULTILINE)
        if m is None:
            return failed
        alert_key = m.group(1)
        return repo_id, alert_num, repo_key, alert_key


    def get_alert_info(self, issue):
        return self.parse_alert_info(issue.fields.description)


    def fetch_issues(self, jira_project, repo_name, alert_num=None):
        key = self.make_key(repo_name + (('/' + str(alert_num)) if alert_num is not None else ''))
        issue_search = 'project={jira_project} and description ~ "{key}"'.format(
            jira_project=jira_project,
            key=key
        )
        result = list(filter(is_managed, self.jira.search_issues(issue_search, maxResults=0)))
        logging.debug('Search {search} returned {num_results} results.'.format(
            search=issue_search,
            num_results=len(result)
        ))
        return result


    def open_issue(self, issue):
        self.transition_issue(issue, JIRA_REOPEN_TRANSITION)


    def close_issue(self, issue):
        self.transition_issue(issue, JIRA_CLOSE_TRANSITION)


    def transition_issue(self, issue, transition):
        jira_transitions = {t['name'] : t['id'] for t in self.jira.transitions(issue)}
        if transition not in jira_transitions:
            logging.error('Transition "{transition}" not available for {issue_key}. Valid transitions: {jira_transitions}'.format(
                transition=transition,
                issue_key=issue.key,
                jira_transitions=list(jira_transitions)
            ))
            raise Exception("Invalid JIRA transition")

        old_issue_status = str(issue.fields.status)

        if old_issue_status == JIRA_OPEN_STATUS and transition == JIRA_REOPEN_TRANSITION or \
        old_issue_status == JIRA_CLOSED_STATUS and transition == JIRA_CLOSE_TRANSITION:
            # nothing to do
            return

        self.jira.transition_issue(issue, jira_transitions[transition])

        logging.info(
            'Adjusted status for issue {issue_key} from "{old_issue_status}" to "{new_issue_status}".'.format(
                issue_key=issue.key,
                old_issue_status=old_issue_status,
                new_issue_status=JIRA_CLOSED_STATUS if (old_issue_status == JIRA_OPEN_STATUS) else JIRA_OPEN_STATUS
            )
        )


    def create_issue(self, repo_id, rule_id, rule_desc, alert_url, alert_num, jira_project):
        result = self.jira.create_issue(
            project=jira_project,
            summary='{rule} in {repo}'.format(rule=rule_id, repo=repo_id),
            description=JIRA_DESC_TEMPLATE.format(
                rule_desc=rule_desc,
                alert_url=alert_url,
                repo_name=repo_id,
                alert_num=alert_num,
                repo_key=self.make_key(repo_id),
                alert_key=self.make_key(repo_id + '/' + str(alert_num))
            ),
            issuetype={'name': 'Bug'}
        )
        logging.info('Created issue {issue_key} for alert {alert_num} in {repo_id}.'.format(
            issue_key=result.key,
            alert_num=alert_num,
            repo_id=repo_id
        ))

        return result


    def sync_repo(self, repo_name, jira_project):
        logging.info('Starting full sync for repository "{repo_name}"...'.format(repo_name=repo_name))

        # fetch code scanning alerts from GitHub
        cs_alerts = []
        try:
            cs_alerts = {self.make_key(repo_name + '/' + str(a['number'])): a for a in self.get_alerts(repo_name)}
        except HTTPError as httpe:
            # if we receive a 404, the repository does not exist,
            # so we will delete all related JIRA alert issues
            if httpe.response.status_code != 404:
                # propagate everything else
                raise

        # fetch issues from JIRA and delete duplicates and ones which can't be matched
        jira_issues = {}
        for i in self.fetch_issues(repo_name):
            _, _, _, key = self.get_alert_info(i)
            if key in jira_issues:
                logging.info('Deleting duplicate jira alert issue {key}.'.format(key=i.key))
                i.delete()   # TODO - seems scary, are we sure....
            elif key not in cs_alerts:
                logging.info('Deleting orphaned jira alert issue {key}.'.format(key=i.key))
                i.delete()   # TODO - seems scary, are we sure....
            else:
                jira_issues[key] = i

        # create missing issues
        for key in cs_alerts:
            if key not in jira_issues:
                alert = cs_alerts[key]
                rule = alert['rule']

                jira_issues[key] = self.create_issue(
                    repo_name,
                    rule['id'],
                    rule['description'],
                    alert['html_url'],
                    alert['number'],
                    jira_project
                )

        # adjust issue states
        for key in cs_alerts:
            alert = cs_alerts[key]
            issue = jira_issues[key]
            istatus = str(issue.fields.status)
            astatus = alert['state']

            if astatus == 'open':
                self.open_issue(issue)
            else:
                self.close_issue(issue)


    def make_key(self, s):
        sha_1 = hashlib.sha1()
        sha_1.update(s.encode('utf-8'))
        return sha_1.hexdigest()
