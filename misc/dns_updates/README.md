# SQS/Lambda-based DNS update system

This directory contains all the required AWS resources to create a copy of the SQS/Lambda workflow to process DNS update requests.

The AWS resources are defined in Terraform files. The source code and packaging tools for the Lambda Function is in the [`lambda/` directory](lambda).

Note: these resources and code/tools are only provided as an example. Some modification may be required to make them work within a VIC-based environment.
