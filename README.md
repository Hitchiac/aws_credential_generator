# aws_credential_generator
#### Overview
* ###### Purpose
    * Script to handle templating credentials for various accounts for the AWS CLI
* ###### Features
    * Handles automatically generating MFA OTP Codes if the MFA Secret is provided
    * Handles normal users with no Account MFA enabled
    * Verbosity mode to track scripts actions
* ###### Compatibility
    * Cross compatible across Windows/Linux
    * Compatible for Python Versions 2.7+
    * Compatible for Commercial, Gov Cloud, and China Regions

#### Tool Docs
* ###### Subcommands
  * Subcommand | Description
    ---------- | -------------
    aws_credential_generator.py generate | Generates the credentials file
    aws_credential_generator.py profile | Shows a table of available profiles and their aliases
* ###### Generate Arguments
  * Arguments | Description
    --------- | -----------
    -h --help | Shows tool usage on command line
    -v --verbose | Toggle to show verbose descriptions of tool actions
    -f --file {{ file }} | file override to read in instead of ~/.aws/real_credentials
    -o --output {{ file }} | file override to output credentials to instead of ~/.aws/credentials
    -d --duration {{ number }} | sts token duration override to use instead of 43200
* ###### Profile Arguments
  * Arguments | Description
    --------- | -----------
    -h --help | Shows tool usage on command line
    -v --verbose | Toggle to show verbose descriptions of tool actions
    -f --file {{ file }} | file override to use instead of ~/.aws/real_credentials

#### INI Configuration File
* ###### Example
```
    [title]
    aws_access_key_id = AAAAAAAAAAAAAAAAAAAA
    aws_secret_access_key = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    mfa_secret = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    alias = alias_name
    description = profile description
    region = us-east-1
    output = json
    skip = true
```
* ###### Fields
  * Field | Description
    --------- | -----------
    aws_access_key_id | AWS Access Key ID for user account
    aws_secret_access_key | AWS Secret Access Key for user account
    mfa_secret | MFA OTP secret for user account
    alias | Name you want to refer to profile with cli (--profile alias)
    description | Description of account for 'profile subcommand'
    region | Default region for the AWS Credentials
    output | Default output for AWS API call returns
    skip | Optional value for accounts with no MFA Secret set to manually input OTP Code

* ###### Fields
  * ###### MFA Secret and Skip
    ```
    MFA Overview:
      - This is an optional value containing the OTP Secret set in the INI Sections
      - If this value is set, the OTP Code will be automatically generated
      - If this value is omitted, and 'skip' is not set, the user will be prompted...
          > Is MFA Enabled on Account 'title (alias)'? [y/n]: █
              ● Yes: User is prompted again to input their MFA OTP Code...
                  > Input MFA OTP Code for Account 'title (alias)': █
              ● No: User doesn't receive any more prompts and credentials are captured without gathering STS Tokens
            
    Skip Overview:
      - This is an optional field that is for accounts that do not have MFA enabled
      - If this is set to any value, then it will be interpreted as True
      - When the mfa_secret field is unset and skip is true, MFA is assumed to not be configured and no prompts will show
  * ###### Alias
    ```
    Overview:
      - Alias is an optional field, if this is omitted, the profiles section name will be used
    
    Example INI:
      [option_a]
      aws_access_key_id = AAAA
      aws_secret_access_key = AAAA
      alias = override
    
      [option_b]
      aws_access_key_id = AAAA
      aws_secret_access_key = AAAA
      
     Result
       option_a: aws sts get-caller-identity --profile override
       option_b: aws sts get-caller-identity --profile option_b
     
    ```
  * ###### Description
    ```
    ./aws_credentials_generator.py profile
    Profile           Alias             Description
    ---------------   ---------------   --------------------
    friends_account | friends_account | Friends AWS Account
    personal        | personal        | My Personal
    work            | work            | AWS Account for Work
    ```
* ###### Other
  * ###### MFA Secret Console Location
    <img src="/images/mfa_secret_location.PNG" width="300" height="323">
