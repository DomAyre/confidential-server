import io
import os
import zipfile


def zip_directory(absolute_target: str) -> io.BytesIO:
    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(absolute_target):
            for file in files:
                full_path = os.path.join(root, file)
                zf.write(
                    full_path,
                    arcname=os.path.relpath(full_path, start=absolute_target)
                )

    memory_file.seek(0)

    return memory_file
