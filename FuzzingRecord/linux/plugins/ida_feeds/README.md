# IDA FLIRT Signature Tools

# Notes

Can be run as a standalone app (launch app_entry) using IDALIB or as an IDAPython plugin.

# Install

The packages should be installed in the interpreter that IDA is using 

`python3 -m pip install -r requirements.txt` 

## Linux & OSX 

`ln -s $(pwd) $HOME/.idapro/plugins/ida_feeds`

## Windows 

`mklink /D "%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_feeds" "%cd%"` 
