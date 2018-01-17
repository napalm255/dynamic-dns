Dynamic DNS
===========

This project can be used as a self hosted dynamic dns solution using amazon web services (aws).

### Technologies Used

- CloudFormation
- CodePipeline
- CodeBuild
- CodeDeploy
- Lambda
- API Gateway
- Route 53

### Setup Pipeline

The setup process uses ansible to deploy the initial cloudformation template.

```
pip install -r requirements_setup.txt
ansible-playbook setup.yml
```

The initial setup will create the pipeline and build process, hook to github and trigger a build.
By the end you should have a working stack.

### Requirements

- AWS Credentials and Config ([Boto3 Config](https://boto3.readthedocs.io/en/latest/guide/configuration.html))
- SSM Parameter
- GitHub Repository
- GitHub OAUTH Token
- API Gateway Custom Domain
