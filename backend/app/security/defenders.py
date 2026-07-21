import os
import bleach
from fastapi import HTTPException, status, Depends
from pydantic import BaseModel


def sanitize_input_text(text: str) -> str:
    """
    Strips out all HTML tags, script elements, and dangerous attributes
    to neutralize Stored XSS vectors before they hit the database.
    """
    if not text:
        return text
    return bleach.clean(text, tags=[], attributes={}, strip=True)


def secure_file_path(base_directory: str, user_filename: str) -> str:
    """
    Prevents LFI and Directory Traversal attacks (e.g., passing ../../../etc/passwd)
    by verifying that the resolved final path strictly resides inside the base directory.
    """
    absolute_base = os.path.abspath(base_directory)
    full_path = os.path.abspath(os.path.join(absolute_base, user_filename))
    
    if not full_path.startswith(absolute_base + os.sep) and full_path != absolute_base:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security Violation: Invalid file path boundary manipulation detected."
        )
    return full_path


async def verify_admin_role(current_admin: dict):
    """
    FastAPI dependency gating. Ensures the authenticated session profile
    explicitly possesses an authorized admin role flag before the path acts.
    """
    if not current_admin or current_admin.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ACCESS_DENIED: Insufficient security clearance level.",
        )
    return current_admin