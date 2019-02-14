### pygithub-webhook:
- serverless app for keeping track of git commit hashes per file on s3

### Quick deployment
- Install npm
```
$ sudo apt install npm
```
- Install serverless framework
```
$ npm install serverless -g
```
- Install App dependencies
```
$ npm install
```
- Install python3-pip
```
sudo apt install python3-pip -y
```
### Configuration
- create/update repos.json from repos.json.example with valid settings
- create/update serverless.yml from serverless.yml.example with valid settings
- an s3 bucket is required to dump data, app sets file to public

### App Deployment
``` 
$ serverless deploy
```
