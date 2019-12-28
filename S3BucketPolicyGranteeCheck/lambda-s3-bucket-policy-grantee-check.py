"""
Lambda function to poll Config for non-compliant resources.

Notifications are sent to an SNS topic.
"""

import boto3

# AWS Config settings
ACCOUNT_ID = boto3.client('sts').get_caller_identity()['Account']
CONFIG_CLIENT = boto3.client('config')
CONFIG_RULE = "S3-Bucket-Policy-Grantee-Check"

# AWS SNS Settings
SNS_CLIENT = boto3.client('sns')
SNS_TOPIC = 'arn:aws:sns:us-east-1:' + ACCOUNT_ID + ':' + 'S3-Bucket-Policy-Grantee-Check-SnsTopic'
SNS_SUBJECT = 'S3 Bucket Policy is non-compliant: ' + ACCOUNT_ID


def lambda_handler(event, context):
    # Get compliance details
    non_compliant_detail = CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=CONFIG_RULE, ComplianceTypes=['NON_COMPLIANT'])

    if len(non_compliant_detail['EvaluationResults']) > 0:
        print(
            'The following resource(s) are not compliant with AWS Config rule: ' + CONFIG_RULE)

        non_compliant_resources = ''

        for result in non_compliant_detail['EvaluationResults']:
            resource_type = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']

            if resource_type == 'AWS::S3::Bucket':
                non_compliant_resources = non_compliant_resources + \
                    result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'] + '\n'

        sns_message = 'AWS Config Compliance Update\n\n Rule: ' \
            + CONFIG_RULE + '\n\n' \
            + 'The following resource(s) are not compliant:\n' \
            + non_compliant_resources

        #'''
        SNS_CLIENT.publish(TopicArn=SNS_TOPIC,
                           Message=sns_message, Subject=SNS_SUBJECT)
        #'''

    else:
        print('No non-compliant resources detected.')
