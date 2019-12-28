import json
import boto3
import configparser
import re

def lambda_handler(event, context):
    data = event['detail']['requestParameters']
    if (data == None):
        print('User did not manage to create role')
    else:
        role_name = event['detail']['requestParameters']['roleName']
        iam_client = boto3.client('iam')
        iam_role = iam_client.get_role(RoleName=role_name)['Role']
        
        # Retrieve ID of the account in which the function is running
        this_account_id = context.invoked_function_arn.split(':')[4]
        
        # Get the list of allowed AWS principals and service principals
        parser = configparser.ConfigParser()
        parser.read('expected.ini')
        expected_servicePrincipals = parser.get('servicePrincipals', 'services').split(',')
        expected_awsPrincipals = parser.get('awsPrincipals', 'account_id').split(',')
        
        # Add this_account_id to be one of the expected_awsPrincipals
        expected_awsPrincipals.append(this_account_id)
        
        # Permission boundary (Pb) policy to be attached to the non-compliant role
        # The policy used here is a customer managed policy that should already exists
        # in the account where the Lambda function is running in
        Pb_policy = 'arn:aws:iam::' + this_account_id + ':policy/pb_quarantine_policy'
        
        # Check the principal in the role's trust policy
        assume_role_policy = iam_role['AssumeRolePolicyDocument']
        assume_role_principal = assume_role_policy['Statement'][0]['Principal']
        if ('AWS' in assume_role_principal):
            # Check that the account numbers are in the approved list
            # If the account numbers are not in the approved list, attach that pb_quarantine_policy
            if type(assume_role_principal['AWS']) is list:
                for principal in assume_role_principal['AWS']:
                    # AWS principal is typically in the format of arn:aws:iam::${Account_Id}:user/*
                    # so we will take the first occurrence of the account id in the AWS principal string
                    account_id = re.search(r'[0-9]{12}', principal).group()
                    if account_id not in expected_awsPrincipals:
                        iam_client.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=Pb_policy)
                    else:
                        pass
            else:
                principal = assume_role_principal['AWS']
                account_id = re.search(r'[0-9]{12}', principal).group()
                if account_id not in expected_awsPrincipals:
                    iam_client.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=Pb_policy)
                else:
                    pass
        else:
            # Define the regex pattern to find. Service principals are usually in the format of
            # <service-name>.amazonaws.com. We don't want .amazonaws.com so we are looking for 
            # everything before the first period. 
            find = re.compile(r"^[^.]*")
            if type(assume_role_principal['Service']) is list:
                for principal in assume_role_principal['Service']:
                    # group() returns the whole match pattern
                    service = re.search(find, principal).group()
                    print('service is ' + service) 
                    if service not in expected_servicePrincipals:
                        iam_client.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=Pb_policy)
                    else:
                        pass
            else:
                principal = assume_role_principal['Service']
                service = re.search(find, principal).group()
                if service not in expected_servicePrincipals:
                    iam_client.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=Pb_policy)
                else:
                    pass
