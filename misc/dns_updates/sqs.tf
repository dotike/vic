# This tf stack contains all the SQS-related resources for the Lambda/SQS DNS update system

# SQS queue that takes incoming DNS update requests
resource "aws_sqs_queue" "dns_updates" {
  name                       = "dns_updates"
  visibility_timeout_seconds = 90
  message_retention_seconds  = 604800
  redrive_policy             = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.dns_updates_failed.arn}\",\"maxReceiveCount\":3}"
}

# Dead-letter queue for "dns_updates" queue, above (where failed messages are sent after 3 tries)
resource "aws_sqs_queue" "dns_updates_failed" {
  name                       = "dns_updates_failed"
  visibility_timeout_seconds = 1
  message_retention_seconds  = 1209600
}

# SNS topic that receives any Cloudwatch Alarms related to processing DNS updates
resource "aws_sns_topic" "process_dns_updates" {
  name = "process_dns_updates"
}

# Topic subscription to send Alarms to Pagerduty
resource "aws_sns_topic_subscription" "process_dns_updates_pagerduty" {
  topic_arn              = "${aws_sns_topic.process_dns_updates.arn}"
  protocol               = "https"
  # the 'endpoint' URL is created in Pagerduty by adding a "Amazon Cloudwatch" integration to a service. Or... you can use this one :)
  endpoint               = "https://events.pagerduty.com/integration/f893eebf604e48e89a2bfbf267ab317f/enqueue"  # "Automated Infrastructure Alerts (Emergency)"
  endpoint_auto_confirms = "true"
}

# Cloudwatch Alarm to monitor queue length for failed DNS updates
resource "aws_cloudwatch_metric_alarm" "sqs-dns_updates_failed-queue_not_empty" {
  alarm_name        = "sqs-dns_updates_failed-queue_not_empty"
  alarm_description = "doc/blob/master/teams/ops/alerts.md#sum-approximatenumberofmessagesvisible-greaterthanthreshold-00-for-queuename-dns_updates_failed"

  namespace   = "AWS/SQS"
  dimensions {
    QueueName = "${aws_sqs_queue.dns_updates_failed.name}"
  }

  # Trigger if the 'failed DNS change requests' SQS queue has any messages in it
  metric_name         = "ApproximateNumberOfMessagesVisible"
  comparison_operator = "GreaterThanThreshold"
  statistic           = "Sum"
  threshold           = "0"
  period              = "300"  # SQS only reports metrics in 5 minute intervals, so anything less is pointless
  evaluation_periods  = "1"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "${aws_sns_topic.process_dns_updates.arn}"
  ]
}

# Cloudwatch Alarm to monitor queue age for incoming DNS updates
resource "aws_cloudwatch_metric_alarm" "sqs-dns_updates-queue_filling_up" {
  alarm_name        = "sqs-dns_updates-queue_filling_up"
  alarm_description = "doc/blob/master/teams/ops/alerts.md#sum-approximateageofoldestmessage-greaterthanthreshold-360-for-queuename-dns_updates"

  namespace   = "AWS/SQS"
  dimensions {
    QueueName = "${aws_sqs_queue.dns_updates.name}"
  }

  # Trigger if the 'DNS change requests' SQS queue has not been emptied for at least six minutes
  metric_name         = "ApproximateAgeOfOldestMessage"
  comparison_operator = "GreaterThanThreshold"
  statistic           = "Sum"
  threshold           = "360"  # message age in seconds
  period              = "300"  # SQS only reports metrics in 5 minute intervals, so anything less is pointless
  evaluation_periods  = "1"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "${aws_sns_topic.process_dns_updates.arn}"
  ]
}
