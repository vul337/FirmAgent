import os
import json
from pathlib import Path
import platform

def get_user_config_path():
    """Get the path to the user's config file based on platform following IDA's user directories."""
    system = platform.system()

    if system == "Windows":
        # On Windows, use the %APPDATA%\Hex-Rays\IDA Pro directory
        config_dir = Path(os.getenv('APPDATA')) / "Hex-Rays" / "IDA Pro"
    else:
        # On macOS and Linux, use ~/.idapro
        config_dir = Path.home() / ".idapro"

    # Return the full path to the config file (now in JSON format)
    user_config_path = config_dir / "ida-config.json"
    return user_config_path

def create_default_config(user_config_path):
    """Create a default config file in JSON format."""
    # Create a default JSON config structure
    default_config = {
        "Paths": {
            "ida-install-dir": ""
        }
    }

    # Create the directory if it doesn't exist
    user_config_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the default config to the user-specific config file
    with user_config_path.open('w') as configfile:
        json.dump(default_config, configfile, indent=4)

    print(f"Default config file created at {user_config_path}")
    return default_config

def load_config():
    """Load the user-specific config from JSON file."""
    user_config_path = get_user_config_path()

    if not user_config_path.exists():
        # If the config file doesn't exist, create it with default values
        config = create_default_config(user_config_path)
    else:
        # If the config file exists, load it
        with user_config_path.open('r') as configfile:
            config = json.load(configfile)

    return config

def set_ida_install_dir(new_path):
    """Set the IDA installation directory in the user-specific JSON config file."""
    # Get the user-specific config path
    user_config_path = get_user_config_path()

    # Load the existing config or create default if missing
    config = load_config()

    # Set the new IDA installation directory path
    config['Paths']['ida-install-dir'] = new_path

    # Write the changes back to the user-specific config file
    with user_config_path.open('w') as configfile:
        json.dump(config, configfile, indent=4)

    print(f"IDA installation directory set to: {new_path}")

def get_ida_install_dir():
    """Retrieve the IDA installation directory from the JSON config file."""
    config = load_config()
    return config['Paths'].get('ida-install-dir', None)
