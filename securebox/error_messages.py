"""Safe user-facing explanations shared by API responses and item views."""

ERROR_MESSAGES = {
    "invalid_request": "Some information is missing or doesn't look right. Review the fields and try again.",
    "request_too_large": "This request is larger than allowed. Choose a smaller file or remove some information, then try again.",
    "unauthenticated": "SecureBox couldn't confirm your sign-in. Sign in again, then retry.",
    "session_check_failed": "Your session may have expired. Reload the page and sign in again, then retry.",
    "permission_denied": "You don't have permission to do this. Use the account that owns this item.",
    "forbidden": "You don't have permission to do this with this account.",
    "not_found": "This item isn't available. It may have been deleted, or you may need to sign in to the account that owns it.",
    "profile_not_found": "No saved profile was found. Save a profile first, then try again.",
    "conflict": "This action can't be completed right now. Refresh the page and try again.",
    "registration_conflict": "We couldn't create an account with those details. Try a different username, or sign in if you may already have an account.",
    "invalid_credentials": "The username or password is incorrect.",
    "registration_closed": "You can't create an account right now. Sign in if you already have an account, or ask the project maintainer when registration will reopen.",
    "invalid_invitation": "The invitation code is missing or incorrect. Check the code and try again.",
    "invalid_filename": "The file name couldn't be accepted. Rename it to a simple name that ends with its file type, then try again.",
    "invalid_file": "We couldn't read this file. It may be damaged or saved in an unsupported format. Choose a valid supported file and try again.",
    "file_too_large": "This file is too large. Reduce its size and try again. Maximums are 5 MiB for images, 10 MiB for PDF/DOCX/XLSX, and 20 MiB for MP4.",
    "unsupported_file_type": "This file type isn't supported. Choose a JPG, JPEG, PNG, PDF, DOCX, XLSX, or MP4 file.",
    "mime_mismatch": "The file contents don't match the selected file type. Choose the original file without renaming it, then try again.",
    "image_dimensions_exceeded": "This image's pixel dimensions are too large. Resize it smaller and try again.",
    "invalid_office_file": "This isn't a valid DOCX or XLSX document, or the file may be damaged. Save it again in the correct format and try again.",
    "archive_limits_exceeded": "This document has too much embedded data. Remove large or extra embedded content, then try again.",
    "active_office_content": "This document contains macros or embedded content that SecureBox doesn't accept. Save a macro-free DOCX or XLSX copy and try again.",
    "external_relationship": "This document links to files or content outside itself. Remove those links and upload a self-contained copy.",
    "active_pdf_content": "This PDF includes forms, scripts, or attachments that SecureBox doesn't accept. Save a clean PDF without those features and try again.",
    "invalid_mp4": "This video couldn't be opened as an MP4. Export it as a standard MP4 and try again.",
    "video_limits_exceeded": "This video is outside the supported limits. Use an MP4 up to 20 MiB, 10 minutes long, and 1080p or lower.",
    "video_validation_unavailable": "SecureBox can't check videos right now. Try again later. If the issue continues, contact the project maintainer.",
    "payload_integrity_mismatch": "SecureBox couldn't verify the uploaded file after receiving it. Select the file again and retry; if this happens again, contact the project maintainer.",
    "processing_failed": "The file could not be processed. Check that it is supported and not password-protected, then upload it again.",
    "native_backend_failed": "Encryption couldn't finish on this server. Try uploading again later. If it keeps failing, contact the project maintainer.",
    "retry_limit_exceeded": "SecureBox stopped after several processing attempts. Delete this item and upload it again. Contact the project maintainer if it happens again.",
    "benchmark_failed": "The comparison couldn't finish. Try again later. If the problem continues, contact the project maintainer.",
    "storage_quota_exceeded": "Your storage limit has been reached. Delete an item or choose a smaller file before uploading again.",
    "active_job_exists": "Another upload or comparison is still running. Wait for it to finish, then try again.",
    "rate_limited": "You've tried this too many times. Wait a little while, then try again.",
    "invalid_state": "This item isn't ready for that action yet. Wait for its upload or processing to finish, then try again.",
    "service_unavailable": "SecureBox can't reach a required service right now. Wait a moment and try again.",
    "internal_error": "Something went wrong while completing your request. Try again. If it keeps happening, contact the project maintainer.",
}


def error_message(code: str | None) -> str:
    """Return a safe, user-facing explanation for a public error code."""
    return ERROR_MESSAGES.get(code or "", ERROR_MESSAGES["internal_error"])


def public_error_code(code: object) -> str:
    """Expose only documented error codes; unknown codes are internal failures."""
    return code if isinstance(code, str) and code in ERROR_MESSAGES else "internal_error"

