#!/usr/bin/env python3
"""
karton-cape-submitter: Submit samples from MWDB to CAPEv2 for dynamic analysis.

This Karton module listens for new file samples in MWDB and automatically
submits them to CAPE sandbox for analysis. It applies prefiltering based
on file type and size.

Author: Claude AI (automated malware analysis pipeline)
Version: 1.0.0
"""

import os
import logging
import time
from typing import Optional
from dataclasses import dataclass

import requests
from karton.core import Karton, Task, Config
from mwdblib import MWDB

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)


@dataclass
class CapeConfig:
    """Configuration for CAPE connection."""
    submit_url: str
    tls_verify: bool
    ca_bundle: Optional[str]
    tags_default: str
    allowed_tags: list
    retry_max: int
    retry_backoff: int
    max_mb_per_file: int


def load_cape_config() -> CapeConfig:
    """Load CAPE configuration from environment variables."""
    return CapeConfig(
        submit_url=os.getenv('CAPE_SUBMIT_URL', 'https://127.0.0.1/apiv2/tasks/create/file/'),
        tls_verify=os.getenv('CAPE_TLS_VERIFY', 'false').lower() == 'true',
        ca_bundle=os.getenv('CAPE_CA_BUNDLE') or None,
        tags_default=os.getenv('CAPE_TAGS_DEFAULT', 'win11,x64'),
        allowed_tags=os.getenv('CAPE_ALLOWED_TAGS', 'dotnet,dotnet6-9,java,pdf,vcredist,win11,x64').split(','),
        retry_max=int(os.getenv('CAPE_RETRY_MAX', '5')),
        retry_backoff=int(os.getenv('CAPE_RETRY_BACKOFF_SECONDS', '60')),
        max_mb_per_file=int(os.getenv('MAX_MB_PER_FILE', '50'))
    )


# File types to submit to CAPE (based on magic/classification)
SUBMIT_TYPES = {
    'PE32 executable',
    'PE32+ executable',
    'MS-DOS executable',
    'DLL',
    'Microsoft Word',
    'Microsoft Excel',
    'Microsoft PowerPoint',
    'Rich Text Format',
    'PDF document',
    'script',
    'VBA',
    'JavaScript',
    'VBScript',
    'PowerShell',
    'JAR',
    'Java',
    'MSI',
    'LNK',
    'HTA',
    'batch',
    'ELF',
}

# File extensions to submit
SUBMIT_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd', '.ps1',
    '.vbs', '.js', '.jse', '.wsf', '.wsh', '.hta', '.msi', '.jar',
    '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm',
    '.pdf', '.rtf', '.lnk', '.elf', '.py', '.zip', '.rar', '.7z'
}


def should_submit_sample(file_name: str, file_type: str, file_size: int, max_size_mb: int) -> bool:
    """
    Determine if a sample should be submitted to CAPE based on prefiltering rules.

    Args:
        file_name: Original filename
        file_type: MWDB file type/classification
        file_size: File size in bytes
        max_size_mb: Maximum allowed file size in MB

    Returns:
        True if sample should be submitted, False otherwise
    """
    # Check file size
    max_size_bytes = max_size_mb * 1024 * 1024
    if file_size > max_size_bytes:
        log.info(f"Skipping {file_name}: size {file_size} exceeds max {max_size_bytes}")
        return False

    # Check file type
    if file_type:
        for submit_type in SUBMIT_TYPES:
            if submit_type.lower() in file_type.lower():
                return True

    # Check file extension
    if file_name:
        ext = os.path.splitext(file_name.lower())[1]
        if ext in SUBMIT_EXTENSIONS:
            return True

    log.info(f"Skipping {file_name}: type '{file_type}' not in submit list")
    return False


def determine_cape_tags(file_type: str, allowed_tags: list, default_tags: str) -> str:
    """
    Determine appropriate CAPE tags based on file type.

    Args:
        file_type: MWDB file type classification
        allowed_tags: List of allowed CAPE tags
        default_tags: Default tags to use

    Returns:
        Comma-separated string of CAPE tags
    """
    tags = set(default_tags.split(','))

    if file_type:
        ft_lower = file_type.lower()

        # .NET samples need dotnet tag
        if '.net' in ft_lower or 'msil' in ft_lower:
            if 'dotnet' in allowed_tags:
                tags.add('dotnet')

        # Java samples need java tag
        if 'java' in ft_lower or 'jar' in ft_lower:
            if 'java' in allowed_tags:
                tags.add('java')
                tags.discard('win11')  # Java doesn't need Windows

        # PDF samples need pdf tag
        if 'pdf' in ft_lower:
            if 'pdf' in allowed_tags:
                tags.add('pdf')

    # Filter to only allowed tags
    tags = {t for t in tags if t in allowed_tags}

    return ','.join(sorted(tags))


def submit_to_cape(
    cfg: CapeConfig,
    file_content: bytes,
    file_name: str,
    sha256: str,
    tags: str
) -> Optional[int]:
    """
    Submit a sample to CAPE for analysis.

    Args:
        cfg: CAPE configuration
        file_content: File content bytes
        file_name: Original filename
        sha256: SHA256 hash of the file
        tags: CAPE analysis tags

    Returns:
        CAPE task ID if successful, None otherwise
    """
    verify = cfg.ca_bundle if cfg.ca_bundle else cfg.tls_verify

    for attempt in range(1, cfg.retry_max + 1):
        try:
            files = {'file': (file_name, file_content)}
            data = {'tags': tags}

            log.info(f"Submitting {sha256[:16]}... to CAPE (attempt {attempt}/{cfg.retry_max})")

            resp = requests.post(
                cfg.submit_url,
                files=files,
                data=data,
                verify=verify,
                timeout=120
            )

            if resp.status_code == 200:
                result = resp.json()
                if 'data' in result and 'task_ids' in result['data']:
                    task_ids = result['data']['task_ids']
                    if task_ids:
                        task_id = task_ids[0]
                        log.info(f"CAPE task created: {task_id} for {sha256[:16]}...")
                        return task_id

                log.warning(f"Unexpected CAPE response: {result}")
                return None

            elif resp.status_code == 429:
                log.warning(f"CAPE rate limited, waiting {cfg.retry_backoff}s...")
                time.sleep(cfg.retry_backoff)
                continue

            else:
                log.error(f"CAPE submission failed: {resp.status_code} - {resp.text[:200]}")

        except requests.exceptions.RequestException as e:
            log.error(f"CAPE connection error: {e}")

        if attempt < cfg.retry_max:
            time.sleep(cfg.retry_backoff)

    return None


class CapeSubmitter(Karton):
    """
    Karton module that submits samples from MWDB to CAPE for dynamic analysis.

    Listens for new file samples and submits appropriate ones to CAPE sandbox.
    """

    identity = "karton.cape-submitter"
    version = "1.0.0"

    # Listen for new file samples
    filters = [
        {"type": "sample", "stage": "recognized"},
        {"type": "sample", "stage": "unrecognized"},
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cape_cfg = load_cape_config()

        # Initialize MWDB client for tagging
        mwdb_url = self.config.get("mwdb", "api_url", fallback="http://mwdb:8080/api")
        mwdb_key = self.config.get("mwdb", "api_key", fallback="")
        self.mwdb = MWDB(api_url=mwdb_url, api_key=mwdb_key) if mwdb_key else None

        log.info(f"CapeSubmitter initialized - CAPE URL: {self.cape_cfg.submit_url}")

    def process(self, task: Task) -> None:
        """Process incoming sample task."""
        sample = task.get_resource("sample")
        if not sample:
            log.warning("Task has no sample resource")
            return

        sha256 = sample.sha256
        file_name = sample.name or f"{sha256}.bin"
        file_type = task.headers.get("type", "")

        log.info(f"Processing sample: {sha256[:16]}... ({file_name})")

        # Download sample content
        file_content = sample.content
        file_size = len(file_content)

        # Prefilter check
        if not should_submit_sample(
            file_name, file_type, file_size, self.cape_cfg.max_mb_per_file
        ):
            return

        # Determine CAPE tags
        tags = determine_cape_tags(
            file_type,
            self.cape_cfg.allowed_tags,
            self.cape_cfg.tags_default
        )

        # Submit to CAPE
        task_id = submit_to_cape(
            self.cape_cfg,
            file_content,
            file_name,
            sha256,
            tags
        )

        # Tag sample in MWDB with CAPE task ID
        if task_id and self.mwdb:
            try:
                mwdb_file = self.mwdb.query_file(sha256)
                if mwdb_file:
                    mwdb_file.add_tag(f"cape:{task_id}")
                    mwdb_file.add_tag("cape-submitted")
                    log.info(f"Tagged {sha256[:16]}... with cape:{task_id}")
            except Exception as e:
                log.warning(f"Failed to tag sample in MWDB: {e}")


if __name__ == "__main__":
    CapeSubmitter().loop()
