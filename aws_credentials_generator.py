#!/usr/bin/env python

#Standard Imports
import argparse
import base64
import datetime
import hashlib
import hmac
import math
import os
import re
import stat
import sys
import time

#External Imports
import boto3
from botocore.exceptions import ClientError

#Version Specifics
if (sys.version_info > (3, 0)):
    import configparser as ConfigParser
else:
    import ConfigParser
    input = raw_input

#Set Default ConfigParser Section
ConfigParser.DEFAULTSECT = "default"

def main():
    """Main Controller.

    :return: None
    """
    #Parse CLI
    args = argparse_cli()

    #Set Global Control Variables
    global_controllers(args)
    
    #Validate CLI Args
    args = validate_cli(args)

    #Get Profiles from File
    profiles = get_credentials(args)

    #Subcommand Operator
    subcommand_operator(args, profiles)

    return None

def global_controllers(args):
    """Generate credentials for different profiles.

    :param args: Dictionary with arguments from CLI options
    :return: None
    """
    #Declare as Global
    global AWS_PATH
    global AUTOCORRECT
    global REAL_PATH
    global VERBOSE
    
    #Set Values
    AWS_PATH    = ".aws/credentials"
    AUTOCORRECT = True
    REAL_PATH   = ".aws/real_credentials"
    VERBOSE     = args.get("verbose")

    return None

def validate_cli(args):
    """Validates the options from CLI.

    :param args: Dictionary with arguments from CLI options
    :return args: Dictionary with arguments from CLI options
    """
    #Vars from CLI
    arg_credfile = args.get("file")
    arg_outfile = args.get("output")
    arg_token_duration = args.get("duration")

    #Get/Validate 'Credentials' File Path
    if arg_credfile is None:
        credentials_file = _get_default_credentials_path(mode="credentials")
    else:
        credentials_file = _get_custom_credentials_path(arg_credfile)

    #Get/Validate 'Output' File Path
    if arg_outfile is None:
        output_file = _get_default_credentials_path(mode="output")
    else:
        output_file = _get_custom_credentials_path(arg_outfile)

    #Validate Token Duration
    if arg_token_duration != None:
        if (arg_token_duration < 900) or (arg_token_duration > 129600):
            arg_token_duration = 43200
   
    #Set In Arguments Dictionary 
    args["file"] = credentials_file
    args["output"] = output_file
    args["duration"] = arg_token_duration

    return args

def subcommand_operator(args, profiles):
    """Function to handle subcommands from CLI.

    :param args: Dictionary with arguments from CLI options
    :param profiles: Dictionary with objects from profiles in Credentials File
    :return: None
    """
    #Get Subcommand Action 
    action = args.get("action")
    
    #Handle Subcommand Functions
    if action == "profile":
        show_profiles(profiles)
    elif action == "generate":
        generate_credentials(args, profiles)

    return None

def generate_credentials(args, profiles):
    """Generate credentials for different profiles.

    :param args: Dictionary with arguments from CLI options
    :param profiles: Dictionary with objects from profiles in Credentials File
    :return: None
    """
    #Track MFA Call Success
    table_success = []
    table_failed = []

    #Get Command line Arguments
    arg_outfile = args.get("output")
    arg_token_duration = args.get("duration") 

    #Varaibles for Inplace Terminal Displays
    stdout_int_length = len(profiles)
    stdout_str_length = len(str(stdout_int_length))

    #Length of Terminal Text to Backspace
    backspace_template = (b"\r" * len("> Generating Profile {0}/{0}".format(stdout_str_length))).decode()

    #Format Template For Dynamic Strings
    stdout_template = "> Generating Profile {{0:0{0}d}}/{{1}}".format(stdout_str_length)

    #Iter Profiles to Get Account Credentials
    for i, alias in enumerate(profiles, start=1):
        #Track Iterations to Standard Out
        sys.stdout.write(stdout_template.format(i, stdout_int_length))
        sys.stdout.write(backspace_template)
        sys.stdout.flush()
    
        #Boolean to Get STS Token or Not
        is_mfa_enabled = True

        #Boolean to Generate STS Token or Get Manually
        is_input_needed = False

        #Get Profile Object
        profile = profiles[alias]
            
        #Check if User Needs to Input MFA Code
        if profile.get("skip") != None:
            is_mfa_enabled = False
        elif (profile.get("mfa_secret") is None) and (profile.get("skip") is None):
            #Parameters for Input Prompt
            prompt = "> Is MFA Enabled on Account '{0} ({1})'? [y/n]: ".format(profile["acct_title"], alias)
            err_prompt = "> Invalid choice, must be [y, n]"
            condition = lambda x: (False, True)[x.lower() in ["y", "n"]]
            custom_return = lambda x: (False, True)[x == "y"]
            
            #Get User Input
            is_mfa_enabled = _while_prompt(prompt, err_prompt, condition, custom_return)

            #Swap Boolean for STS Block if True
            if is_mfa_enabled == True:
                is_input_needed = True

        #Get Access Key Credentials if MFA is Enabled
        if is_mfa_enabled == True:
            #Create Client
            stsClient = boto3.client(
                "sts",
                aws_access_key_id=profile["aws_access_key_id"],
                aws_secret_access_key=profile["aws_secret_access_key"],
                region_name=profile["region"]
            )

            #Get Caller Identity
            try:
                user_arn = stsClient.get_caller_identity()
                user_arn = user_arn.get("Arn")
            except ClientError as e:
                #Fail on Error
                err = "profile '{0} ({1})' failed with error message '{2}'".format(profile["acct_title"], alias, str(e))
                program_err(err)
                
            #Regex to Get MFA Device ARN
            mfa_device_arn = re.sub("user", "mfa", user_arn)

            #Generate OTP or Get User Input
            if is_input_needed == False:
                otp_token = _generate_otp(profile["mfa_secret"])
            else:
                prompt = "> Input MFA OTP Code for Account '{0} ({1})': ".format(profile["acct_title"], alias)
                err_prompt = "> OTP must be 6 digits long"
                condition = lambda x: (False, True)[len(x) == 6]
                otp_token = _while_prompt(prompt, err_prompt, condition)

            #Get STS Credentials 
            try:
                #Get STS Token
                session_credentials = stsClient.get_session_token(
                    DurationSeconds=arg_token_duration, 
                    SerialNumber=mfa_device_arn, 
                    TokenCode=otp_token
                )

                #Update Dictionary
                profile["status"] = "success"
                profile["aws_access_key_id"] = session_credentials["Credentials"]["AccessKeyId"]
                profile["aws_secret_access_key"] = session_credentials["Credentials"]["SecretAccessKey"]
                profile["aws_session_token"] = session_credentials["Credentials"]["SessionToken"]
            
                #Log
                info = "< profile '{0}' handled successfully".format(profile["acct_title"])
                program_info(info, show_log=VERBOSE)
            except ClientError as e:
                #Client Error
                e_operation = e.operation_name
                e_code = e.response["Error"]["Code"]
                e_message = e.response["Error"]["Message"]

                #Update Dictionary Status
                profile["status"] = "{0} ({1}): {2}".format(e_operation, e_code, e_message)
              
                #Log
                info = "< profile '{0} ({1})' failed with error message '{2}'".format(profile["acct_title"], alias, str(e))
                program_info(info, VERBOSE)
        else:
            #Update Dictionary Status
            profile["status"] = "success"
     
        #Set New Profile In Place
        profiles[alias] = profile

    #Open Existing Outfile
    config = ConfigParser.RawConfigParser()
    config.read(arg_outfile)

    #Add Profile to Config
    for alias in profiles:
        #Data to Table Tracker List
        if profiles[alias]["status"] == "success":
            #Add Data to Success Table
            tmp_data = [
                profiles[alias]["acct_title"], 
                profiles[alias]["acct_alias"],
                (str(arg_token_duration) + "s")
            ]
            table_success.append(tmp_data)
        else:
            #Add Data to Failed Table
            tmp_data = [
                profiles[alias]["acct_title"], 
                profiles[alias]["acct_alias"],
                profiles[alias]["status"]
            ]
            table_failed.append(tmp_data)
            
            #Log 
            info = "{0} failed with error message {1}".format(alias, profile["status"])
            program_info(info, VERBOSE)
            
            #Skip Iteration
            continue

        #Add Profile if Missing and Handle Version Dependencies
        if (config.has_section(alias) == False):
            if (sys.version_info > (3, 0)):
                config.add_section(alias)
            else:
                if alias != ConfigParser.DEFAULTSECT:
                    config.add_section(alias)


        #Get Account Credentials 
        aws_access_key_id       = profiles[alias]["aws_access_key_id"]
        aws_secret_access_key   = profiles[alias]["aws_secret_access_key"]
        aws_session_token       = profiles[alias].get("aws_session_token")
        aws_region              = profiles[alias]["region"]
        aws_output              = profiles[alias]["output"]

        #Add STS Credentials to Config
        config.set(alias, "AWS_ACCESS_KEY_ID", aws_access_key_id)
        config.set(alias, "AWS_SECRET_ACCESS_KEY", aws_secret_access_key)
        config.set(alias, "REGION", aws_region)
        config.set(alias, "OUTPUT", aws_output)
 
        #Add Session Token if MFA Configured Account
        if aws_session_token != None:
            config.set(alias, "AWS_SESSION_TOKEN", aws_session_token)

    #Write Credentials to Output File
    with open(arg_outfile, "w+") as outfile:
        config.write(outfile)

    #Get Session End Time
    end_time = datetime.datetime.now() + datetime.timedelta(seconds=arg_token_duration)
    end_time = end_time.strftime("%b %d, %I:%M:%S %p")    
 
    #Get Time
    sesh_hours = arg_token_duration // 3600
    sesh_mins = arg_token_duration // 60 % sesh_hours

    #Handle Success Data Table
    headers = ["Success", "Alias", "Duration"]
    table_success_str = _create_table(headers, table_success, separator=" | ")
    print(table_success_str + "\n")
    
    #Handle Failed Data Table
    if len(table_failed) > 0:
        headers = ["Failed", "Alias", "Error"]
        table_failed_str = _create_table(headers, table_failed, separator=" | ")
        print(table_failed_str + "\n")

    #Display
    print(">>> AWS Credentials written to {0}".format(arg_outfile))
    print(">>> Credentials valid for '{0} hours' and '{1} minutes' until '{2}'".format(sesh_hours, sesh_mins, end_time))

    return None

def show_profiles(profiles):
    """Prints out table displaying profile titles and profile aliases.

    :param profiles: Dictionary with objects from profiles in Credentials File
    :return: None
    """
    #Define Headers for Table
    headers = ["Profile", "Alias", "Description"]

    #Get Data from Profile Object Array
    data = []
    for profile in sorted(profiles):
        tmp = [
            profiles[profile]["acct_title"], 
            profiles[profile]["acct_alias"],
            profiles[profile]["description"]
        ]
        data.append(tmp)

    #Create Table
    table = _create_table(headers, data, separator=" | ")

    #Show Table
    print(table)

    return None

def get_credentials(args):
    """Get custom 'aws credentials' file path and validate it exists.

    :param args: Dictionary with arguments from CLI
    :return section_tracker: List with objects from profiles in Credentials File
    """
    #Local Tracking Variables
    section_tracker = {}    #Track Profile Dictionaries
    section_aliases = {}    #Track Alias Information
    
    #Credentials Command Line Argument
    arg_file = args.get("file")

    #Read INI Credentials File to ConfigParser Object
    profile_parser = ConfigParser.ConfigParser()
    profile_parser.read(arg_file)
 
    #All Sections Titles to Array (Not Including Default)
    section_iterator = profile_parser.sections()
    
    #Get Default Section Dictionary
    default_section = dict(profile_parser.defaults())

    #If Default is Section is Declared, Append to Sections Array
    if default_section:
        section_iterator.append(default_section)

    #Iterate Sections
    for section in section_iterator:
        #Get Section(str) or Default(dict) Section
        if isinstance(section, str):
            #Get Section From Parser Object
            tmp_obj = dict(profile_parser.items(section))
            
            #Set Original Section Title
            tmp_obj["acct_title"] = section
            
            #If Account Alias is Missing from INI, Use Section Name
            if tmp_obj.get("acct_alias") is None:
                tmp_alias = section
            else:
                tmp_alias = tmp_obj.get("acct_alias")
            
            #Set Alias
            tmp_obj["acct_alias"] = tmp_alias
        else:
            #Get Default Section From List
            tmp_obj = section

            #Set Default Section Title
            tmp_obj["acct_title"] = "default"
            
            #If Account Alias is Missing from INI, Use 'default'
            if tmp_obj.get("acct_alias") is None:
                tmp_alias = "default"
            else:
                tmp_alias = tmp_obj.get("acct_alias")
            
            #Set Default Alias
            tmp_obj["acct_alias"] = tmp_alias

        #Handle Profile Descriptions
        if tmp_obj.get("description") is None:
            tmp_obj["description"] = ""

        #Track Aliases
        if section_aliases.get(tmp_alias):
            #Get Duplication Number
            dupe_num = section_aliases[tmp_alias] + 1

            #Append Duplication Number to Duped Alias
            dupe_alias = "{0}_{1}".format(tmp_alias, str(dupe_num))

            #Update Duplication Value on Original Alias
            section_aliases[tmp_alias] = dupe_num

            #Add New Alias in Dictionary
            section_aliases[dupe_alias] = 1

            #Update Dictionary
            tmp_obj["acct_alias"] = dupe_alias
        else:
            #Add New Alias in Dictionary
            section_aliases[tmp_alias] = 1

        #Append to Tracker
        section_tracker[tmp_obj["acct_alias"]] = tmp_obj

    #Log
    info = "< gathered real credentials from '{0}'".format(arg_file)
    program_info(info, show_log=VERBOSE)
    
    return section_tracker

def argparse_cli():
    """Argparse Code to read in users CLI arguments.

    :return args_dict: Dictionary containing parameters from CLI Arguments
    """
    #Get Name of Executed Python File
    script_name = os.path.basename(__file__)

    #Main Parser Description Text
    parser_text = (
        "{0} generate [-f --file] [-o --output] [-d --duration] [-v --verbose]\n"
        "{0} profile [-f --file] [-v --verbose]"
    ).format(script_name)

    #Create Main Parser
    parser = argparse.ArgumentParser(
        description=parser_text, 
        add_help=True, prog=script_name, 
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    #Subparser Object
    subparsers = parser.add_subparsers(dest="action")
    subparsers.required = True

    #Generate | Subparser
    temp_help = "subcommand to generate credentials" 
    generate_subparser = subparsers.add_parser("generate", help=temp_help, formatter_class=argparse.RawTextHelpFormatter)
    
    #Generate | Credentials File Location Override
    temp_help = "credentials file to use" 
    generate_subparser.add_argument("-f", "--file", type=str, help=temp_help, required=False, default=None)

    #Generate | Output File Location Override
    temp_help = "output location for credentials file" 
    generate_subparser.add_argument("-o", "--output", type=str, help=temp_help, required=False, default=None)
    
    #Generate | Token Duration Override
    temp_help = "token duration to use" 
    generate_subparser.add_argument("-d", "--duration", type=int, help=temp_help, required=False, default=43200)
    
    #Generate | Run Script Verbose Mode
    temp_help = "run file in verbose mode"
    generate_subparser.add_argument("-v", "--verbose", help=temp_help, action="store_true")
    
    #Profile | Subparser
    temp_help = "subcommand to view available profiles" 
    profile_subparser = subparsers.add_parser("profile", help=temp_help, formatter_class=argparse.RawTextHelpFormatter)
    
    #Profile | Credentials File Location Override
    temp_help = "credentials file to use" 
    profile_subparser.add_argument("-f", "--file", type=str, help=temp_help, required=False, default=None)
    
    #Profile | Run Script Verbose Mode
    temp_help = "run file in verbose mode"
    profile_subparser.add_argument("-v", "--verbose", help=temp_help, action="store_true")
    
    #Arguments to Dictionary
    args_dict = vars(parser.parse_args())
    
    return args_dict

def _get_default_credentials_path(mode, auto_chmod=True):
    """Get default 'aws credentials' file path (~/.aws/credentials) and validate it exists.

    :return credentials_file: String that has full path to credentials file
    """
    #Expand Users Home Directory
    user_home = os.path.expanduser("~")

    #Get Credentials File
    if mode == "credentials":
        aws_credentials = ".aws{0}real_credentials".format(os.sep)
    else:
        aws_credentials = ".aws{0}credentials".format(os.sep)
    
    #Get Filpath
    filepath = os.path.join(user_home, aws_credentials)
    filepath_dirname = os.path.dirname(filepath)
   
    #Create '.aws' Directory if it Doesn't Exists
    if os.path.isdir(filepath_dirname) != True:
        os.makedirs(filepath_dirname)
        info = "< created directory '{0}'".format(filepath_dirname)
        program_info(info, show_log=VERBOSE)
    
    #Create Credentials File if it Doesn't Exists
    if os.path.isfile(filepath) != True:
        with open(filepath, "w"): pass
        info = "< created file '{0}'".format(filepath)
        program_info(info, show_log=VERBOSE)

    #Chmod Directory to 700
    if (auto_chmod == AUTOCORRECT) and (mode == "credentials"):
        #Validate Files Have 400/600/700 Permissions
        valid_permissions = _validate_file_permissions(filepath_dirname, [400, 600, 700], fail=False)
        
        #Chmod File and Log if Directory Has Bad Permissions
        if valid_permissions == False:
            os.chmod(filepath_dirname, stat.S_IRWXU)
            info = "< permissions on directory '{0}' changed to '{1}'".format(filepath_dirname, oct(stat.S_IRWXU))
            program_info(info, show_log=VERBOSE)

    #Chmod File to 700
    if (auto_chmod == AUTOCORRECT):
        #Validate Files Have 400/600/700 Permissions
        valid_permissions = _validate_file_permissions(filepath, [400, 600, 700], fail=False)
        
        #Chmod File and Log if Directory Has Bad Permissions
        if valid_permissions == False:
            os.chmod(filepath, stat.S_IRWXU)
            info = "< permissions on file '{0}' changed to '{1}'".format(filepath, oct(stat.S_IRWXU))
            program_info(info, show_log=VERBOSE)

    return filepath

def _get_custom_credentials_path(path, auto_chmod=True):
    """Get custom 'aws credentials' file path and validate it exists.

    :param filepath: String with custom filepath to credentials file
    :return credentials_file: String that has full path to credentials file
    """
    #Handle Absolute/Relative Paths
    if os.path.isabs(path):
        filepath = path
    else:
        filepath = os.path.abspath(path)

    #Ensure Filepath Exists and Log
    if os.path.exists(filepath) != True:
        with open(filepath, "w"): pass
        info = "< created file '{0}'".format(filepath)
        program_info(info, show_log=VERBOSE)
    
    #Validate Files Have 400/600/700 Permissions
    file_valid_permissions = _validate_file_permissions(filepath, [400, 600, 700], fail=False)

    #Chmod File to 700 and Log
    if auto_chmod == AUTOCORRECT and file_valid_permissions == False:
        os.chmod(filepath, stat.S_IRWXU)
        info = "< permissions on file '{0}' changed to '{1}'".format(filepath, oct(stat.S_IRWXU))
        program_info(info, show_log=VERBOSE)

    return filepath

def _validate_file_permissions(filepath, permissions, fail=False):
    """Validate the permissions on a file match a specified octet.

    :param filepath: String of path to file
    :param permissions: List of Integers of desired file permission (000 - 777)
    :param fail: Boolean to dictate if function fails instead of returns
    :return is_valid: Boolean showing result of file permissions and input permissions comparison
    """
    #Permissions Parameter to Integer List
    if isinstance(permissions, str):
        permissions = list(int(permissions))
    elif isinstance(permissions, int):
        permissions = list(permissions)

    #Validate Input Permissions is in Permissions Range
    for octet in permissions:
        if (octet < 000) or (octet > 777):
            err = "given permission '{0}' out of range (000-777)".format(octect)
            program_err(err)

    #Boolean to Track Results
    is_valid = True

    #File Stats as Octet
    file_stat = oct(os.stat(filepath).st_mode)
    
    #Get File Permission Information
    file_permissions = int(str(file_stat[-3:]))

    #Validate File Permissions Are Matching
    if file_permissions not in permissions:
        is_valid = False
    
    #Fail if Permissions Do Not Match and Fail is True
    if (is_valid is False) and (fail is True):
        err = "File permissions not correct ({0}), use 'chmod {1} {2}'".format(file_permissions, permissions, filepath)
        program_err(err)

    #Log
    info = "< file permissions '{0}' for file '{1}' validated".format(file_permissions, filepath)
    program_info(info, show_log=VERBOSE)
    
    return is_valid

def _while_prompt(prompt, err, condition, custom=None):
    """Loops prompt until given condition is satisfied.

    :param prompt: String with prompt to show user for gathering inputs
    :param err: String with prompt to show user on input errors
    :param condition: Callable object to use for while loop input condition
    :param custom: Callable object that runs custom function to return custom values outside of input string
    :return: Input string from user unless custom is overloaded, then custom value from callable object
    """

    #Get Initial Input
    input_str = input(prompt)
   
    #Iterate Until Condition is Met
    while condition(input_str) != True:
        #Print Error
        print("{0}\n".format(err))

        #Get New Input
        input_str = input(prompt)
  
    #Custom Return if Callable Object
    if callable(custom):
        return custom(input_str)
    else:
        return input_str

def _create_table(headers, table, separator=None):
    """Create a table based on 2D array for user display.

    :param headers: Array with table headers
    :param table: 2D Array with table data
    :param separator: String that specifies separator between table columns
    :return print_str: String with formatted table to print
    """
    #Get Headers Length
    headers_length = len(headers)

    #Column Length Map
    column_lengths = dict()
    for i in range(len(headers)):
        column_lengths[str(i)] = None

    #Ensure Headers Match Table Sublists
    for sublist in table:
        if len(sublist) != headers_length:
            err = "headers do not match the length of table items"
            program_err(err)
        else:
            for i in range(len(sublist)):
                index_str = str(i)
                sublist_str = str(sublist[i])
                if column_lengths[index_str] == None:
                    column_lengths[index_str] = len(sublist_str)
                elif len(sublist_str) > column_lengths[index_str]:
                    column_lengths[index_str] = len(sublist_str)

    #Change Length if Headers Bigger than Row Data
    for i in range(len(headers)):
        if len(headers[i]) > column_lengths[str(i)]:
            column_lengths[str(i)] = len(headers[i])

    #Declare Final String
    print_str = ""
    column_delimiter = separator if separator else "   "
    delimiter_length = len(column_delimiter)
    header_delimiter = " " * delimiter_length

    #Create Row Template
    row_template = column_delimiter.join(["{{{0}:<{1}}}".format(x, column_lengths[str(x)]) for x in range(len(headers))])
    header_template = header_delimiter.join(["{{{0}:<{1}}}".format(x, column_lengths[str(x)]) for x in range(len(headers))])
    border_template = header_delimiter.join(["-" * column_lengths[str(x)] for x in range(len(headers))])

    #Add Headers
    print_str += "{0}\n{1}\n".format(header_template.format(*headers), border_template)

    #Construct String
    for i, sublist in enumerate(table):
        print_str += row_template.format(*sublist)
        if (i+1) < len(table):
            print_str += "\n"

    #Log
    info = "< generated data table"
    program_info(info, show_log=VERBOSE)
    
    return print_str
    
def _generate_otp(mfa_secret):
    """Generate a time based OTP(One Time Passcode) with a given MFA Secret.

    :param mfa_secret: String secret for MFA device
    :return str_code: String with 6 digit OTP Code for MFA Verification
    """
    #Get Timecode
    current_time = datetime.datetime.now().timetuple()
    temp_time = time.mktime(current_time)
    timecode = int(temp_time / 30)

    #Hasher Vars
    #Get Byte Secret
    missing_padding = len(mfa_secret) % 8
    if missing_padding != 0:
        mfa_secret += "=" * (8 - missing_padding)
    byte_secret = base64.b32decode(mfa_secret, casefold=True)
                                                            
    #Get Byte String
    byte_str_result = bytearray()
    while timecode != 0:
        byte_str_result.append(timecode & 0xFF)
        timecode >>= 8
    byte_string = bytes(bytearray(reversed(byte_str_result)).rjust(8, b"\0"))

    #Create Hash
    hasher = hmac.new(byte_secret, byte_string, hashlib.sha1)
                                                                                                                
    #Get MFA Code
    hmac_hash = bytearray(hasher.digest())
    offset = hmac_hash[-1] & 0xf
    code = ((hmac_hash[offset] & 0x7f) << 24 |
            (hmac_hash[offset + 1] & 0xff) << 16 |
            (hmac_hash[offset + 2] & 0xff) << 8 |
            (hmac_hash[offset + 3] & 0xff))

    #MFA Code to String
    str_code = str(code % 10 ** 6)
    while len(str_code) < 6:
        str_code = "0" + str_code

    #Log
    info = "< generated otp '{0}' at time '{1}'".format(str_code, time.strftime("%Y-%m-%dT%H:%M:%SZ", current_time))
    program_info(info, show_log=VERBOSE)

    #Return
    return str_code

def program_info(info, show_log=False):
    """Log message to Logger under INFO Level.

    :param info: Info message to log
    :param show_log: Prints the output to console if set to True
    :return: None
    """
    #Print if True
    if show_log == True:
        print(info)

    return None

def program_err(err, exception=Exception, show_log=True):
    """Log message to Logger under ERROR Level and exit program execution.

    :param err: Error message to log
    :param show_log: Prints the output to console if set to True
    :return: None (Exits Program)
    """
    #Print if True
    if show_log == True:
        print(err)
    
    #Quit Program
    raise exception(err)

if __name__ == "__main__":
    main()
