"""Utility functions for Firefox forensics extraction."""

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional


def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """Configure logging for the forensics tool.
    
    Args:
        log_level: Logging level (default: INFO).
    
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("firefox_forensics")
    logger.setLevel(log_level)

    # Console handler with formatted output
    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def create_output_directory(base_name: str = "firefox_forensics_output") -> Path:
    """Create output directory structure for forensics results.
    
    Args:
        base_name: Base name for output directory.
    
    Returns:
        Path to output directory root.
    """
    output_dir = Path(base_name)
    
    # Remove existing directory if present
    if output_dir.exists():
        shutil.rmtree(output_dir)
    
    # Create directory structure
    (output_dir / "databases").mkdir(parents=True, exist_ok=True)
    (output_dir / "forensics").mkdir(parents=True, exist_ok=True)
    (output_dir / "reports").mkdir(parents=True, exist_ok=True)
    (output_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    
    return output_dir


def get_timestamp() -> str:
    """Get current timestamp as ISO format string.
    
    Returns:
        Formatted timestamp string.
    """
    return datetime.now().isoformat()


def format_bytes(bytes_value: int) -> str:
    """Format bytes as human-readable string.
    
    Args:
        bytes_value: Number of bytes.
    
    Returns:
        Formatted string (e.g., "1.5 MB").
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} TB"


def validate_profile_path(path: Path) -> bool:
    """Validate Firefox profile directory.
    
    Args:
        path: Path to validate.
    
    Returns:
        True if valid Firefox profile.
    """
    if not path.exists():
        return False
    
    if not path.is_dir():
        return False
    
    # Check for typical Firefox profile files
    markers = ["prefs.js", "places.sqlite", "cookies.sqlite"]
    found = sum(1 for marker in markers if (path / marker).exists())
    
    return found >= 1


def expand_firefox_path(path_str: str) -> Path:
    """Expand and resolve Firefox profile path.
    
    Handles:
    - Home directory expansion (~)
    - Relative paths
    - Profile path shortcuts
    
    Args:
        path_str: Input path string.
    
    Returns:
        Resolved Path object.
    """
    path = Path(path_str).expanduser().resolve()
    return path


def get_profile_info(profile_path: Path) -> dict:
    """Extract basic profile information.
    
    Args:
        profile_path: Path to Firefox profile.
    
    Returns:
        Dictionary with profile metadata.
    """
    info = {
        "path": str(profile_path),
        "name": profile_path.name,
        "exists": profile_path.exists(),
        "is_directory": profile_path.is_dir(),
    }

    if profile_path.exists():
        try:
            # Get profile size
            total_size = sum(
                p.stat().st_size for p in profile_path.glob("**/*") if p.is_file()
            )
            info["total_size"] = total_size
            info["total_size_formatted"] = format_bytes(total_size)

            # Count files
            file_count = sum(1 for _ in profile_path.glob("**/*") if _.is_file())
            info["file_count"] = file_count

            # Check for specific markers
            info["has_prefs"] = (profile_path / "prefs.js").exists()
            info["has_places"] = (profile_path / "places.sqlite").exists()
            info["has_cookies"] = (profile_path / "cookies.sqlite").exists()
            info["has_logins"] = (
                (profile_path / "logins.json").exists()
                or (profile_path / "logins.sqlite").exists()
            )

        except Exception as e:
            info["error"] = str(e)

    return info


def safe_file_copy(src: Path, dst: Path, logger: Optional[logging.Logger] = None) -> bool:
    """Safely copy a file with error handling.
    
    Args:
        src: Source file path.
        dst: Destination file path.
        logger: Optional logger instance.
    
    Returns:
        True if successful.
    """
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        if logger:
            logger.debug(f"Copied {src.name} to {dst}")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Failed to copy {src.name}: {e}")
        return False


def generate_summary_text(title: str, sections: dict) -> str:
    """Generate formatted summary text.
    
    Args:
        title: Title for the summary.
        sections: Dictionary of section_name -> content_lines.
    
    Returns:
        Formatted text string.
    """
    output = f"# {title}\n\n"
    
    for section_name, content in sections.items():
        output += f"## {section_name}\n"
        if isinstance(content, list):
            for item in content:
                output += f"- {item}\n"
        elif isinstance(content, dict):
            for key, value in content.items():
                output += f"- {key}: {value}\n"
        else:
            output += f"{content}\n"
        output += "\n"
    
    return output


def count_table_rows(db_path: Path, table_name: str) -> int:
    """Count rows in a SQLite table.
    
    Args:
        db_path: Path to SQLite database.
        table_name: Name of table.
    
    Returns:
        Number of rows or -1 if error.
    """
    import sqlite3
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM \"{table_name}\"")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return -1


def sanitize_filename(filename: str) -> str:
    """Sanitize a string for use as filename.
    
    Args:
        filename: Original filename.
    
    Returns:
        Sanitized filename.
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(" .")
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename


class ProgressTracker:
    """Track and report progress during extraction."""

    def __init__(self, total_items: int):
        """Initialize progress tracker.
        
        Args:
            total_items: Total number of items to process.
        """
        self.total = total_items
        self.current = 0
        self.completed = []
        self.failed = []

    def increment(self, item_name: str = "", success: bool = True):
        """Increment progress counter.
        
        Args:
            item_name: Name of item being processed.
            success: Whether processing was successful.
        """
        self.current += 1
        if success:
            self.completed.append(item_name)
        else:
            self.failed.append(item_name)

    def get_percentage(self) -> int:
        """Get completion percentage.
        
        Returns:
            Percentage (0-100).
        """
        if self.total == 0:
            return 0
        return int((self.current / self.total) * 100)

    def summary(self) -> str:
        """Get progress summary text.
        
        Returns:
            Formatted summary string.
        """
        return (
            f"Progress: {self.current}/{self.total} "
            f"({self.get_percentage()}%) - "
            f"Completed: {len(self.completed)}, "
            f"Failed: {len(self.failed)}"
        )
