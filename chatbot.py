import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

load_dotenv()
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# Initialize AWS clients
try:
    s3_client = boto3.client('s3')
    ec2_client = boto3.client('ec2')
    iam_client = boto3.client('iam')
except NoCredentialsError:
    s3_client = None
    ec2_client = None
    iam_client = None

class S3BucketContentsArgs(BaseModel):
    bucket_name: str = Field(description="The name of the S3 bucket to inspect")

class EC2InstanceArgs(BaseModel):
    ip_address: str = Field(description="The IP address of the EC2 instance")

class IAMUserArgs(BaseModel):
    username: str = Field(description="The IAM username to check permissions for")

@tool
def check_s3_public_access() -> str:
    """Check which S3 buckets are publicly accessible."""
    if not s3_client:
        return "AWS credentials not configured"
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        if not buckets:
            return "No S3 buckets found"
        public_buckets = []
        private_buckets = []

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            try:
                # check bucket ACL
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            is_public = True
                            break
                # check bucket policy
                if not is_public:
                    try:
                        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                        if policy_status.get('PolicyStatus', {}).get('IsPublic'):
                            is_public = True
                    except ClientError:
                        pass

                if is_public:
                    public_buckets.append(bucket_name)
                else:
                    private_buckets.append(bucket_name)
            except ClientError:
                private_buckets.append(bucket_name)

        result = f"Total buckets: {len(buckets)}\nPublic: {len(public_buckets)}\nPrivate: {len(private_buckets)}"
        if public_buckets:
            result += f"\n\nPublic buckets:\n" + "\n".join(f"  - {b}" for b in public_buckets)
        return result

    except Exception as e:
        return f"Error: {str(e)}"

@tool(args_schema=S3BucketContentsArgs)
def get_s3_bucket_contents(bucket_name: str) -> str:
    """List files and data in an S3 bucket."""
    if not s3_client:
        return "AWS credentials not configured"
    # List objects in the specified S3 bucket
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)
        objects = []
        total_size = 0
        for page in pages:
            for obj in page.get('Contents', []):
                objects.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'modified': obj['LastModified'].strftime('%Y-%m-%d %H:%M')
                })
                total_size += obj['Size']

        if not objects:
            return f"Bucket '{bucket_name}' is empty"
        # Summarize contents
        result = f"Bucket: {bucket_name}\nTotal files: {len(objects)}\nTotal size: {format_bytes(total_size)}\n\nFiles:"
        for obj in objects[:10]:
            result += f"\n  {obj['key']} - {format_bytes(obj['size'])} ({obj['modified']})"
        if len(objects) > 10:
            result += f"\n  ... and {len(objects) - 10} more files"
        return result

    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            return f"Bucket '{bucket_name}' does not exist"
        elif e.response['Error']['Code'] == 'AccessDenied':
            return f"Access denied to bucket '{bucket_name}'"
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

@tool(args_schema=EC2InstanceArgs)
def get_ec2_instance_details(ip_address: str) -> str:
    """Get EC2 instance details by IP address."""
    if not ec2_client:
        return "AWS credentials not configured"
    try:
        # get public IP first
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'network-interface.addresses.association.public-ip', 'Values': [ip_address]}]
        )
        # get private IP if not found
        if not response['Reservations']:
            response = ec2_client.describe_instances(
                Filters=[{'Name': 'private-ip-address', 'Values': [ip_address]}]
            )
        if not response['Reservations']:
            return f"No EC2 instance found with IP {ip_address}"
        instance = response['Reservations'][0]['Instances'][0]

        instance_id = instance['InstanceId']
        instance_type = instance['InstanceType']
        state = instance['State']['Name']
        public_ip = instance.get('PublicIpAddress', 'N/A')
        private_ip = instance.get('PrivateIpAddress', 'N/A')

        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        instance_name = tags.get('Name', 'N/A')

        result = f"Instance ID: {instance_id}\n"
        result += f"Name: {instance_name}\n"
        result += f"Type/Size: {instance_type}\n"
        result += f"State: {state}\n"
        result += f"Public IP: {public_ip}\n"
        result += f"Private IP: {private_ip}"
        return result

    except Exception as e:
        return f"Error: {str(e)}"

@tool(args_schema=IAMUserArgs)
def get_iam_user_permissions(username: str) -> str:
    """Get permissions and policies for an IAM user."""
    if not iam_client:
        return "AWS credentials not configured"

    try:
        user_info = iam_client.get_user(UserName=username)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return f"IAM user '{username}' does not exist"
        return f"Error: {str(e)}"
    try:
        result = f"User: {username}\n"
        result += f"ARN: {user_info['User']['Arn']}\n"
        result += f"Created: {user_info['User']['CreateDate'].strftime('%Y-%m-%d')}\n"

        # get the managed policies
        managed_policies = iam_client.list_attached_user_policies(UserName=username)
        if managed_policies['AttachedPolicies']:
            result += "\nManaged Policies:\n"
            for policy in managed_policies['AttachedPolicies']:
                result += f"  - {policy['PolicyName']}\n"

        # get the inline policies
        inline_policies = iam_client.list_user_policies(UserName=username)
        if inline_policies['PolicyNames']:
            result += "\nInline Policies:\n"
            for policy_name in inline_policies['PolicyNames']:
                result += f"  - {policy_name}\n"

        # get groups
        groups = iam_client.list_groups_for_user(UserName=username)
        if groups['Groups']:
            result += "\nGroups:\n"
            for group in groups['Groups']:
                result += f"  - {group['GroupName']}\n"

        if not managed_policies['AttachedPolicies'] and not inline_policies['PolicyNames'] and not groups['Groups']:
            result += "\nNo permissions assigned"
        return result
    except Exception as e:
        return f"Error: {str(e)}"

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def create_agent():
    llm = ChatOpenAI(api_key=OPENAI_API_KEY, temperature=0, model="gpt-3.5-turbo")
    tools = [
        check_s3_public_access,
        get_s3_bucket_contents,
        get_ec2_instance_details,
        get_iam_user_permissions
    ]

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an AWS assistant. Help users understand their AWS resources using the available tools."),
        ("human", "{input}"),
        ("assistant", "{agent_scratchpad}")
    ])
    agent = create_openai_tools_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=3)

def main():
    print("AWS Account Chatbot\n")
    print("Ask about S3 buckets, EC2 instances, or IAM users.")
    print("Type 'exit' to quit.\n")

    try:
        agent = create_agent()
    except Exception as e:
        print(f"Error: {e}")
        return
    while True:
        try:
            user_input = input("Query: ").strip()
            if user_input.lower() in ['exit', 'quit']:
                print("Goodbye!")
                break

            response = agent.invoke({"input": user_input})
            print(f"\n{response['output']}\n")

        except Exception as e:
            print(f"Error: {str(e)}\n")

if __name__ == "__main__":
    main()