import os
from config.parser import ServerConfig
from flask import send_file

from lib.zip_directory import zip_directory

def fetch(target: str, args: ServerConfig):

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    absolute_target = os.path.join(project_root, target)

    # Ensure target is an actual file or directory and defined in the server
    # configuration. The application shouln't distinguish between files which
    # don't exist and files not included in the configuration.
    if not os.path.exists(absolute_target) or target not in (target.path for target in args.config.serve):
        return f"Target '{target}' does not exist.", 404

    # If it's a file, just send it, if it's a directory, zip it first
    if os.path.isfile(absolute_target):
        return send_file(
            absolute_target,
            download_name=os.path.basename(absolute_target),
            as_attachment=True,
        )
    else:
        return send_file(
            zip_directory(absolute_target),
            download_name=f"{os.path.basename(os.path.normpath(absolute_target))}.zip",
            as_attachment=True,
        )
