# This tf stack contains all the necessary Lambda-related resources for the Lambda/SQS DNS update system

# The actual Lambda function definition.
# This resource takes the "deployment package" (the zipped source code and dependencies) from the filesystem
# relative to this file and uploads it to AWS.
resource "aws_lambda_function" "process_dns_updates" {
  function_name = "process_dns_updates"
  role          = "${aws_iam_role.lambda-process_dns_updates.arn}"
  description   = "Read DNS update requests from SQS and apply the changes to Route53"

  runtime          = "python2.7"
  filename         = "lambda/dist/process_dns_updates.zip"
  handler          = "process_dns_updates.lambda_handler"
  source_code_hash = "${base64sha256(file("lambda/dist/process_dns_updates.zip"))}"

  reserved_concurrent_executions = 2  # allow up to 2 invokations of the Function to be run at once
  timeout                        = 60  # how long the Function can run before being forcibly terminated
  memory_size                    = 128  # in MB. Minimum size is 128 (we don't need nearly that much)

  environment {
    variables        = {
      SQS_QUEUE_NAME = "${aws_sqs_queue.dns_updates.name}"
    }
  }
}

# Grant permission to Cloudwatch to execute the Lambda Function
resource "aws_lambda_permission" "process_dns_updates_cloudwatch_exec" {
  statement_id  = "AllowExecutionFromCloudWatch"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.every_minute.arn}"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.process_dns_updates.function_name}"
}

# Create an Event every 60 seconds that we can use to trigger arbitrary tasks
# Note: this rule can be used to trigger up to 10 targets (just create additional
# aws_cloudwatch_event_target resources.
resource "aws_cloudwatch_event_rule" "every_minute" {
  name                = "every_minute"
  description         = "Trigger target events every 60 seconds"
  schedule_expression = "cron(* * * * ? *)"
}

# Execute the Lambda Function every time the above Event Rule triggers
resource "aws_cloudwatch_event_target" "process_dns_updates_minutely" {
  rule = "${aws_cloudwatch_event_rule.every_minute.name}"
  arn  = "${aws_lambda_function.process_dns_updates.arn}"
}

# Create the required Cloudwatch Logs log group for the Lambda Function
# Note: this log group is automatically created by Lambda, but we want to manually set the retention period
resource "aws_cloudwatch_log_group" "lambda-process_dns_updates" {
  name              = "/aws/lambda/${aws_lambda_function.process_dns_updates.function_name}"
  retention_in_days = "7"
}
