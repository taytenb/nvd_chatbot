# AWS Account Chatbot

A natural language chatbot that uses LangChain to answer questions about your AWS account. Ask it about S3 buckets, EC2 instances, and IAM users in plain English.

## What it does

- Check which S3 buckets are publicly accessible
- List files and data in S3 buckets
- Get EC2 instance details by IP address
- View IAM user permissions and policies

## Setup

You need Python 3.8+, AWS credentials, and an OpenAI API key.

First, install the dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Next, configure your AWS credentials. 

OPENAI_API_KEY=sk-your-openai-key
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=your-secret
AWS_DEFAULT_REGION=us-east-1

You'll also need an OpenAI API key 

Finally, make sure your AWS user has the ReadOnlyAccess policy attached. Go to IAM in the AWS console, find your user, and attach the ReadOnlyAccess policy under permissions.

## Running it

Just run:

python chatbot.py


Then ask questions like:
- "How many S3 buckets are exposed to the public?"
- "What data does the S3 bucket my-logs hold?"
- "What is the size of the EC2 instance with IP 10.0.1.50?"
- "What permissions does the user admin have?"

Type 'exit' or 'quit' when you're done.

## How it works

The chatbot uses four custom LangChain tools that wrap AWS boto3 API calls. When you ask a question, GPT-3.5 figures out which tool to use and calls it with the right parameters. The tools query your AWS account and return the results in a readable format.

The four tools are:
- check_s3_public_access - lists all buckets and checks their public access settings
- get_s3_bucket_contents - shows files in a bucket with sizes and dates
- get_ec2_instance_details - finds EC2 instances by IP and returns details
- get_iam_user_permissions - gets policies and permissions for IAM users

Everything is read-only, so the chatbot can't make any changes to your AWS account.

## Troubleshooting

If you get "AWS credentials not configured", make sure you ran aws configure or created the .env file correctly.

If you get "Access Denied", your IAM user needs the ReadOnlyAccess policy. Add it in the IAM console and wait a minute for it to take effect.

If you get "No such bucket" or "No EC2 instance found", double check the names and IPs you're using. The chatbot can only find resources that actually exist in your account.

## Technical details

Built with LangChain 0.3.0, OpenAI GPT-3.5-turbo, and boto3 1.35.0. Uses python-dotenv for configuration. Requires an internet connection to call AWS and OpenAI APIs.

See SAMPLE_OUTPUT.md for example outputs and TEST_RESULTS.md for actual test results.