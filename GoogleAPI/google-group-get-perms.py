#!/usr/bin/env python
#
# Setup:
# - create OAuth client ID
#    - https://console.developers.google.com/project/600658572628/apiui/credential
# - enable Groups Settings API and Admin SDK
#    - https://console.developers.google.com/project/600658572628/apiui/api
# - Create client_secrets.json
# {
#   "web": {
#     "client_id": "<client_id>",
#     "client_secret": "<client_secret>",
#     "redirect_uris": [],
#     "auth_uri": "https://accounts.google.com/o/auth2/auth",
#     "token_uri": "https://accounts.google.com/o/auth2/token"
#   }
# }
#

import httplib2
import json
from apiclient.discovery import build
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import run

DOMAIN = 'jana.com'

ADMIN_SCOPE = 'https://www.googleapis.com/auth/admin.directory.group'
GROUPS_SCOPE = 'https://www.googleapis.com/auth/apps.groups.settings'
CLIENT_SECRETS = 'client_secrets.json'

def get_creds():
    FLOW = flow_from_clientsecrets(CLIENT_SECRETS, scope=[ADMIN_SCOPE, GROUPS_SCOPE])

    storage = Storage('groupsettings.dat')
    credentials = storage.get()

    if credentials is None or credentials.invalid:
        print 'invalid credentials'
        # Save the credentials in storage to be used in subsequent runs.
        credentials = run(FLOW, storage)

    return credentials


class Run:
    def __init__(self, domain, credentials):
        self.credentials = credentials
        self.group_service = self._create_service('groupssettings', 'v1')

    def _create_service(self, service, version):
        # Create an httplib2.Http object to handle our HTTP requests and authorize it
        # with our good Credentials.
        http = httplib2.Http()
        http = self.credentials.authorize(http)

        service = build(service, version, http=http)
        return service


    def get_domain_groups(self):
        service = self._create_service('admin', 'directory_v1')
        group_list = service.groups().list(domain='jana.com').execute()
        self.groups = self.group_service.groups()
        return group_list

    def get_group_view(self, group):
        return self.groups.get(groupUniqueId=group).execute()['whoCanViewMembership']

    def get_group_join(self, group):
       groups = self.group_service.groups()
       return groups.get(groupUniqueId=group).execute()['whoCanJoin']

if __name__ == '__main__':

    creds = get_creds()
    r = Run(domain=DOMAIN, credentials=creds)
    group_list = r.get_domain_groups()


    group_email_list = []
    for group in group_list['groups']:
        group_email_list.append({ 'email':group['email'], 'name':group['name'], 'whoCanViewMembership':r.get_group_view(group['email']), 'whoCanJoin':r.get_group_join(group['email'])})

    group_email_list.sort()
    print "jana.com groups"
    print "Email\t\t\t\tName\t\t\t\t\tView"
    print "-----------"
    for group in group_email_list:
        print '{0}\t{1}\t{2}\t{3}'.format(group['email'].ljust(30), group['name'].ljust(40), group['whoCanViewMembership'], group['whoCanJoin'])
