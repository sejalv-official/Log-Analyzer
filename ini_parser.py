import configparser

def parse_aws_extension_ini(ini_text):
    """
    Parses the AWS Config Extension INI format.
    Returns a dictionary of {profile_name: role_arn}
    
    Expected format:
    # Comments
    [profile client-name]
    role_arn = arn:aws:iam::123456789012:role/Support
    region = us-east-1
    """
    if not ini_text.strip():
        return {}
        
    parser = configparser.ConfigParser()
    # configparser is strict about duplicate sections, so we disable strict mode if available
    try:
        # ConfigParser uses strict=True by default in python 3.2+
        parser = configparser.ConfigParser(strict=False)
        parser.read_string(ini_text)
        
        profiles = {}
        for section in parser.sections():
            # Handle standard AWS format [profile x] or just [x] from extension
            name = section.replace('profile ', '').strip()
            
            # The extension supports role_arn directly
            if parser.has_option(section, 'role_arn'):
                profiles[name] = parser.get(section, 'role_arn')
            # It also supports account_id + role_name combinations, but user mentioned role_arn replacing it
                
        return profiles
    except Exception as e:
        print(f"Error parsing INI: {e}")
        return {}
