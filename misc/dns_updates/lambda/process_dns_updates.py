#!/usr/bin/env python
"""process_dns_updates

Gets the latest DNS record change requests from SQS and updates the Route53
records accordingly

NOTE: This is intended to be run within an AWS Lambda container! Correct
functionality outside of Lambda cannot be guaranteed.
"""
# builtin modules
import logging
import re
import json
import os

# 3rd party modules
import boto3
import botocore.exceptions

# Pull some config from env (supplied by AWS Lambda)
AWS_REGION = os.environ['AWS_REGION']  # set by Lambda automatically
SQS_QUEUE_NAME = os.environ['SQS_QUEUE_NAME']  # set in Lambda manually

# Set up some global constants
MAX_MESSAGES = 10  # AWS global limit is 10, so let's get up to that amount
WAIT_TIME_SECONDS = 1  # max seconds to wait for a non-empty SQS queue (20 max)
MAX_MESSAGE_RECEIVE_LOOPS = 30  # set a sane limit to prevent infinite loop

# Set up the root logger with a basic StreamHandler set to log INFO and above.
# This is so we can also emit log events from imported modules.
logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)
# Override default handler's format. AWS butchers it with useless info.
logging.getLogger().handlers[0].setFormatter(logging.Formatter(
    '%(levelname)s:%(name)s:%(message)s\r'))
# Set up a local logger so we can log our own messages
log = logging.getLogger(__name__)

# Set up API objects at the module level. Lambda will reuse the runtime
# envionments when possible, meaning the API connections will be reused.
# https://docs.aws.amazon.com/lambda/latest/dg/running-lambda-code.html
SQS_API = boto3.resource('sqs', region_name=AWS_REGION).get_queue_by_name(
    QueueName=SQS_QUEUE_NAME)
R53_API = boto3.client('route53', region_name=AWS_REGION)


class ErrorSearchException(Exception):
    """
    Exception raised when a record name can not be found in a Route53
    InvalidChangeBatch error. If this exception is raised, you should
    check if the error message returned by AWS's API has changed since
    this script was written (check the regex in
    DnsChangeQueue.remove_failed_record_change() for the expected format)
    """
    pass


class DnsChange(object):
    """
    One-stop shop for all your DNS-record-change-request info and actions

    The JSON in each SQS message's body should follow this format:
    {
        "Domain": str(qaolate.com),
        "Action": str(UPSERT),
        "Record": {
            "Name": str(test-record.qaolate.com),
            "Type": str(CNAME),
            "TTL": int(60),
            "Targets": [
                str(test1.example.com),
                str(test2.example.com)
            ]
        }
    }

    Keep in mind that the body JSON is stringified before being sent to SQS so
    all keys and values should be converted into their required data type
    before use
    """

    __hash__ = None  # Instances of this class should not be hashable

    def __init__(self, boto_message):
        """
        Args:
            boto_message (sqs.Message): boto3 object for the SQS message
        """
        # Init some useful class properties
        self._boto_message = boto_message
        self.sent_timestamp = int(boto_message.attributes['SentTimestamp'])
        self.receipt_handle = str(boto_message.receipt_handle)

        # Attributes to be set later
        self.requested = False  # Was this change added to a batch request?
        self.duplicate = False  # Is the change an unused duplicate?
        self.failed = False  # Did the change fail to apply?

        # Process and load the SQS message's body
        self.safe_load_body()

    def delete(self):
        """Delete the message from the queue"""
        self._boto_message.delete()

    def safe_load_body(self):
        """
        Attempt to load the SQS message's body, and get our expected values
        from it. If any expected fields are missing, produce a friendly error
        instead of a traceback.
        """
        # Attempt to parse the message body into JSON
        try:
            self.message_body = json.loads(self._boto_message.body)
        except Exception as e:
            log.error('Could not load SQS message body as JSON (%s)! ' +
                      "Marking message as 'failed'. Message body is:\n" +
                      str(self._boto_message.body), e)
            self.failed = True
            return

        # Attempt to load our attributes from the parsed JSON
        try:
            self.domain = str(self.message_body['Domain']).lower()
            self.action = str(self.message_body['Action']).upper()
            self.record = str(self.message_body['Record']['Name']).lower()
            self.record_type = str(self.message_body['Record']['Type']).upper()
            self.ttl = int(self.message_body['Record']['TTL'])
            self.targets = set()
            for target in self.message_body['Record']['Targets']:
                self.targets.add(str(target).lower())
        except KeyError as e:
            log.error('Could not load required attribute (%s) from message ' +
                      "body! Marking message as 'failed'. Message body is:\n" +
                      str(self.message_body), e)
            self.failed = True
            return


class DnsChangeQueue(object):
    """
    List of DNS changes being requested, and relevant attributes/actions
    """

    def __init__(self, sqs_queue_name):
        """
        Args:
            sqs_queue_name (str, unicode): name of DNS change SQS queue
        """
        self._sqs_api = SQS_API
        self._r53_api = R53_API
        self._messages = None  # list()
        self._record_changes = None  # dict()
        self._hosted_zones = None  # dict()

    @property
    def messages(self):
        """
        Build a list of DnsChange objects, attempting to receive all
        messages in the queue

        Returns:
            list of DnsChange() objects: all received messages from SQS
        """
        if self._messages is None:
            self._messages = list()
            num_received_msgs = None
            receive_loops = 0

            while (num_received_msgs != 0 and
                   receive_loops <= MAX_MESSAGE_RECEIVE_LOOPS):
                receive_loops += 1
                log.info('Starting receive_messages loop #%s', receive_loops)
                num_received_msgs = 0

                messages_from_boto = self._sqs_api.receive_messages(
                    AttributeNames=['SentTimestamp'],
                    MaxNumberOfMessages=MAX_MESSAGES,
                    WaitTimeSeconds=WAIT_TIME_SECONDS)

                for boto_message in messages_from_boto:
                    self._messages.append(DnsChange(boto_message))
                    num_received_msgs += 1
                log.info('Received %s messages from SQS', num_received_msgs)

            log.info('Received a total of %s messages from SQS',
                     len(self._messages))

        return self._messages

    @property
    def record_changes(self):
        """
        Return a slightly easier-to-process data set of our DNS changes.

        When calling this for the first time, it will create a new dict in the
        following format:
        {
            'foo.tld': {
                'record1.foo.tld': [
                    DnsChange(),
                    DnsChange()
                ]
            }
        }

        This makes it much easier to dedupe the changes and build a Route53
        request later.

        Returns:
            dict
        """
        if self._record_changes is None:
            self._record_changes = dict()

            # For each message, add it to the new dict, creating keys if they
            # don't exist already
            for msg in self.messages:
                if msg.failed is not True:
                    self._record_changes.setdefault(
                        msg.domain, {}).setdefault(
                            msg.record, []).append(msg)

        return self._record_changes

    def dedupe_change_requests(self):
        """
        Find and process any 'duplicate' change requests

        If any record has multiple changes (messages) in the queue, keep only
        most recent one, discarding the rest (and marking them as duplicates so
        the unused messages can be deleted later).
        """
        # Find all the records in the queue that have more than one change
        log.info('Removing any duplicate changes')
        for domain in self.record_changes:
            for record in self.record_changes[domain]:
                if len(self.record_changes[domain][record]) > 1:

                    # Sort the change list by timestamp, newest first
                    records = sorted(self.record_changes[domain][record],
                                     key=lambda r: r.sent_timestamp,
                                     reverse=True)
                    log.info(('Found %s change requests for %s. '
                              'Using only the most recent one.'),
                             len(records), record)

                    # Keep only the newest change, marking the others as
                    # duplicates and removing them from the change list
                    while len(records) > 1:
                        records.pop().duplicate = True

                    # Replace the original list with our own
                    self.record_changes[domain][record] = records

    @property
    def hosted_zones(self):
        """
        Create a dict of all our hosted zones and their IDs

        Returns:
            dict: {zone_name: zone_id, ...}
        """
        if self._hosted_zones is None:
            self._hosted_zones = dict()

            # For each hosted zone...
            for zone in self._r53_api.list_hosted_zones_by_name(
                    MaxItems='100')['HostedZones']:
                # Cut off the trailing '.'
                zone_name = '.'.join(zone['Name'].split('.')[:-1])
                # Get just the ID, not the full path
                zone_id = zone['Id'].split('/')[-1:][0]
                # Add to our dict
                self._hosted_zones[zone_name] = zone_id

        return self._hosted_zones

    def generate_r53_changebatch(self, domain):
        """
        Return a properly formed R53 changebatch request dict for a domain

        Args:
            domain (str): which domain to build the changebatch for

        Returns:
            list of dicts
        """
        log.info('Generating Route53 ChangeBatch request for %s', domain)
        changes = list()

        for record in self.record_changes[domain]:
            change = self.record_changes[domain][record][0]

            # Ignore any messages marked as 'failed'
            if change.failed is True:
                continue
            else:
                change.requested = True

            resource_records = list()
            for target in change.targets:
                resource_records.append({'Value': target})

            log.info('Adding change to request: %s -> %s',
                     change.record, change.targets)
            changes.append(
                {
                    'Action': change.action,
                    'ResourceRecordSet': {
                        'Name': change.record,
                        'Type': change.record_type,
                        'TTL': change.ttl,
                        'ResourceRecords': resource_records
                    }
                }
            )

        return {'Changes': changes}

    def mark_failed_record_change(self, domain, error_msg):
        """
        Given an Route53 InvalidChangeBatch error message, determine what
        record failed to change and mark is as failed

        Args:
            domain (str): hosted zone the record lives in
            error_msg (str, unicode): error message returned from Route53
        """
        # Iterate over _every_ requested change and use the record name to...
        for record in self.record_changes[domain]:

            # ...check if it's present within the error message string.
            # If it is, then it's very likely to be the record causing the
            # failure and it should be removed
            if record in error_msg:
                log.error("Removing '%s' from change list and retrying",
                          record)
                for msg in self.record_changes[domain][record]:
                    msg.failed = True

    def commit_changes_to_r53(self):
        """Attempt to make all the changes in our queue"""
        # Before committing, we should remove any duplicate changes
        self.dedupe_change_requests()

        # Run this in a loop so we can re-attempt if we get InvalidChangeBatch
        for domain in self.record_changes:
            while True:

                # Build the changebatch fresh for each loop
                changebatch = self.generate_r53_changebatch(domain)
                log.info('Sending ChangeBatch request for %s', domain)

                try:
                    self._r53_api.change_resource_record_sets(
                        HostedZoneId=self.hosted_zones[domain],
                        ChangeBatch=changebatch)

                # If we get InvalidChangeBatch, try to remove the offending
                # change, and restart the loop
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'InvalidChangeBatch':
                        log.error('Route53: %s', e.message)
                        self.mark_failed_record_change(
                            domain, e.response['Error']['Message'])
                        continue
                    else:
                        raise e

                # If we run out of records to send, let's fail gracefully
                except botocore.exceptions.ParamValidationError as e:
                    if re.search(r'Invalid\slength', e.message) is not None:
                        failed = set(msg.record for msg in self.messages if (
                            msg.failed is True))
                        log.critical(
                            'No more non-failing changes to submit! ' +
                            'For reference, the records that are unable to ' +
                            'updated are:\n' + '\n'.join(failed) +
                            '\nYou may want to process them manually.')
                        break
                    else:
                        raise e

                # If we're still here, everything went well so we should break
                # out of the loop
                else:
                    break

    def delete_processed_messages(self):
        """Delete (or not) all the messages we just processed"""
        # Build a list of messages that we can delete (i.e. successfully
        # processed)
        messages_to_delete = list()
        for message in self.messages:
            if ((message.requested is True or message.duplicate is True) and
                    (message.failed is False)):
                messages_to_delete.append(message)
        log.info('Deleting %s messages (in batches of 10)',
                 len(messages_to_delete))

        # Batch delete messages 10 at a time (max per the API), removing them
        # from the list of messages to delete
        deleted_messages_count = 0
        while len(messages_to_delete) > 0:
            entries = list()
            message_count = 0
            while message_count < 10:
                try:
                    message = messages_to_delete.pop()
                except IndexError:
                    break
                else:
                    entries.append({
                        'Id': str(message_count),
                        'ReceiptHandle': message.receipt_handle
                    })
                    message_count += 1
                    deleted_messages_count += 1
            self._sqs_api.delete_messages(Entries=entries)
        log.info('Deleted %s messages from the SQS queue',
                 deleted_messages_count)


def lambda_handler(event, context):
    """
    Lambda execution handler

    https://docs.aws.amazon.com/lambda/latest/dg/
    python-programming-model-handler-types.html
    """
    # Create our class objects
    dns_change_queue = DnsChangeQueue(SQS_QUEUE_NAME)

    # Update DNS records for each message in the queue
    dns_change_queue.commit_changes_to_r53()

    # Clean up the messages we just processed
    dns_change_queue.delete_processed_messages()
