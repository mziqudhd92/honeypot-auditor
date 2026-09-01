def match_git_always_missing(text: str) -> str | None:
    """git-upload-pack always ERR no such repository — no ref advertisement."""
    blob = text or ""
    low = blob.lower()
    if "err no such repository" in low and "refs/" not in low and "capability" not in low:
        return "git-upload-pack always ERR no such repository"
    return None
