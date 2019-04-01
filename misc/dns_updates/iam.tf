# This tf stack contains all the necessary IAM roles, permissions, etc for the Lambda/SQS DNS update system

# Every Lambda Function needs to have an associated IAM Role.
# It's highly recommended that each Function has a unique Role, to prevent permissions overlap.
resource "aws_iam_role" "lambda-process_dns_updates" {
  name = "lambda-process_dns_updates"
  path = "/"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
POLICY
}

# Let's give that Function the required permissions it needs to operate.
# NOTE: I'm writing a single, inline policy here for simplicity's sake,
# but you can split this up using groups, managed policies, etc however you like.
resource "aws_iam_role_policy" "process_dns_updates" {
  name = "process_dns_updates"
  role = "${aws_iam_role.lambda-process_dns_updates.name}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sqs:GetQueueUrl",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:DeleteMessageBatch"
      ],
      "Resource": [
        "${aws_sqs_queue.dns_updates.arn}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/<HOSTEDZONEID>",
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:GetHostedZone*",
        "route53:ListHostedZones*",
        "route53:TestDNSAnswer"
      ],
      "Resource": "*"
    },
    {
      "Effect":"Allow",
      "Action":[
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource":[
        "arn:aws:logs:::log-group:${aws_cloudwatch_log_group.lambda-process_dns_updates.name}"
      ]
    }
  ]
}
POLICY
}
