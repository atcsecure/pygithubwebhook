#!/usr/bin/env python
import io
import os
import re
import sys
import json
import subprocess
import ipaddress
import hmac
from hashlib import sha1
from flask import Flask, request, abort
import requests
import boto3
if os.environ.get('USE_EC2', None) == 'true':
    from botocore.utils import InstanceMetadataFetcher
    from botocore.credentials import InstanceMetadataProvider

"""
Conditionally import ProxyFix from werkzeug if the USE_PROXYFIX environment
variable is set to true.  If you intend to import this as a module in your own
code, use os.environ to set the environment variable before importing this as a
module.

.. code:: python

    os.environ['USE_PROXYFIX'] = 'true'
    import flask-github-webhook-handler.index as handler

"""
class FilehashMap:
    def __init__(self, datadict):
        self.hashmap = datadict

    def additem(self, filename, filehash):
        self.hashmap[str(filename)] = filehash

    def delitem(self, item):
        #del self.hashMap[str(item)]
        self.hashmap.pop(str(item), None)

    def displayhashmap(self):
        return self.hashmap


if os.environ.get('USE_PROXYFIX', None) == 'true':
    from werkzeug.contrib.fixers import ProxyFix

if sys.version_info[0] >= 3:
    unicode = str

app = Flask(__name__)
app.debug = os.environ.get('DEBUG') == 'true'

#REPOS_JSON_PATH = os.environ['REPOS_JSON_PATH']
REPOS_JSON_PATH = './repos.json'


@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return 'OK'
    elif request.method == 'POST':
        # Store the IP address of the requester
        request_ip = ipaddress.ip_address(u'{0}'.format(request.remote_addr))

        # If VALIDATE_SOURCEIP is set to false, do not validate source IP
        if os.environ.get('VALIDATE_SOURCEIP', None) != 'false':

            # If GHE_ADDRESS is specified, use it as the hook_blocks.
            if os.environ.get('GHE_ADDRESS', None):
                hook_blocks = [unicode(os.environ.get('GHE_ADDRESS'))]
            # Otherwise get the hook address blocks from the API.
            else:
                hook_blocks = requests.get('https://api.github.com/meta').json()[
                    'hooks']

            # Check if the POST request is from github.com or GHE
            for block in hook_blocks:
                if ipaddress.ip_address(request_ip) in ipaddress.ip_network(block):
                    break  # the remote_addr is within the network range of github.
            else:
                if str(request_ip) != '127.0.0.1':
                    abort(403)

        if request.headers.get('X-GitHub-Event') == "ping":
            return json.dumps({'msg': 'Hi!'})
        if request.headers.get('X-GitHub-Event') != "push":
            return json.dumps({'msg': "wrong event type"})

        repos = json.loads(io.open(REPOS_JSON_PATH, 'r').read())

        payload = json.loads(request.data)
        repo_meta = {
            'name': payload['repository']['name'],
            'owner': payload['repository']['owner']['name'],
        }

        # Try to match on branch as configured in repos.json
        match = re.match(r"refs/heads/(?P<branch>.*)", payload['ref'])
        if match:
            repo_meta['branch'] = match.groupdict()['branch']
            repo = repos.get(
                '{owner}/{name}/branch:{branch}'.format(**repo_meta), None)

            # Fallback to plain owner/name lookup
            if not repo:
                repo = repos.get('{owner}/{name}'.format(**repo_meta), None)

        if repo and repo.get('path', None):
            # Check if POST request signature is valid
            key = repo.get('key', None)
            if key:
                signature = request.headers.get('X-Hub-Signature').split(
                    '=')[1]
                if type(key) == unicode:
                    key = key.encode()
                mac = hmac.new(key, msg=request.data, digestmod=sha1)
                if not compare_digest(mac.hexdigest(), signature):
                    abort(403)

        if repo.get('action', None):
            for action in repo['action']:
                subp = subprocess.Popen(action, cwd=repo.get('path', '.'))
                subp.wait()

        if repo.get('s3bucket', None):
            s3bucketname = repo.get('s3bucket')
        else:
            print('missing s3 bucketname')
            abort(500)
        if repo.get('s3key', None):
            s3key = repo.get('s3key')
        else:
            print('missing s3 filename')
            abort(500)

        print('s3 connection')

        if os.environ.get('USE_EC2', None) == 'true':
            provider = InstanceMetadataProvider(iam_role_fetcher=InstanceMetadataFetcher(
                timeout=1000, num_attempts=2))
            creds = provider.load()
            session = boto3.Session(
                aws_access_key_id=creds.access_key,
                aws_secret_access_key=creds.secret_key,
                aws_session_token=creds.token
            )
            s3 = session.resource('s3').Bucket(s3bucketname)
        else:
            s3 = boto3.resource('s3')
            bucket = s3.Bucket(s3bucketname)
        json.load_s3 = lambda f: json.load(bucket.Object(key=f).get()['Body'])
        json.dump_s3 = lambda obj, f: bucket.Object(key=f).put(Body=json.dumps(obj))
        #s3 fetch
        s3data = json.load_s3(s3key)
        datad = FilehashMap(s3data)
        commithash = payload['after']
        #z=[x[y] for x in mydict['commits'] for y in x] -
        for commit in payload['commits']:
            for z in commit['added']:
                print(z)
                datad.additem(z, commithash)
            for z in commit['modified']:
                print(z)
                datad.additem(z, commithash)
            for z in commit['removed']:
                datad.delitem(z)
                print(z)

        print('s3 upload')
        json.dump_s3(datad.displayhashmap(), s3key)
        #set perms
        s3objacl = s3.ObjectAcl(s3bucketname, s3key)
        response = s3objacl.put(ACL='public-read')
        print('s3 done')
        return 'OK'


compare_digest = hmac.compare_digest

if __name__ == "__main__":
    try:
        port_number = int(sys.argv[1])
    except:
        port_number = 8880
    if os.environ.get('USE_PROXYFIX', None) == 'true':
        app.wsgi_app = ProxyFix(app.wsgi_app)
    app.run(debug=True, host='0.0.0.0', port=port_number)


# vim: tabstop=2 softtabstop=0 expandtab shiftwidth=2 smarttab
