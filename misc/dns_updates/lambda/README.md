# process_dns_updates

This directory contains everything necessary to develop and build the [`process_dns_updates` AWS Lambda Function](https://us-west-1.console.aws.amazon.com/lambda/home?region=us-west-1#/functions/process_dns_updates).

This Function reads DNS change requests from an SQS queue and applies them in Route53.

## Deploying changes to this code

If you need to make any changes to the code of the Lambda Function, you'll need to follow the following workflow:

- Make your changes to [`process_dns_updates.py`](process_dns_updates.py)
- If any 3rd-party dependencies were changed/added/removed, update the [`requirements.txt` file](requirements.txt)
- Create a PR for the code changes and get your PR reviewed and approved by a fellow Ops team member
- Re-build the [Lambda deployment package](dist/process_dns_updates.zip): `make package` (from this directory)
- Use Terraform to upload the new deployment package to Lambda:
  - `terraform plan -out=./plan` and review the proposed changes. You should only see changes to the Lambda function's `source_code_hash` and possibly `source_code_size` attributes.
  - If everything looks good with the plan: `terraform apply ./plan`
  - Commit the new deployment package (`lambda/dist/process_dns_updates.zip`)
- Merge your PR
- Confirm that the Lambda function is using the new version of your code:
  - Open the [Lambda Function in the AWS Console](https://us-west-1.console.aws.amazon.com/lambda/home?region=us-west-1#/functions/process_dns_updates)
  - Using the inline code editor, ensure whatever changes you made are represented there
  - _Note: it may take a few minutes for the code editor to reflect a recently-updated deployment package_
