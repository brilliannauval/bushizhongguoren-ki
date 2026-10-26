from __future__ import annotations

import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import PurePath
from xml.etree import ElementTree

from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader


@dataclass(frozen=True)
class ValidatedFile:
    kind: str
    mime_type: str
    display_name: str
    size: int


class InvalidUpload(ValueError):
    def __init__(self, code: str, message: str = "The upload did not pass validation."):
        super().__init__(message)
        self.code = code


MIME_BY_EXTENSION = {
    ".jpg": ("image", {"image/jpeg"}),
    ".jpeg": ("image", {"image/jpeg"}),
    ".png": ("image", {"image/png"}),
    ".pdf": ("pdf", {"application/pdf"}),
    ".docx": ("docx", {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}),
    ".xlsx": ("xlsx", {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}),
    ".mp4": ("video", {"video/mp4"}),
}
MAX_BYTES = {
    ".jpg": 5 * 1024 * 1024,
    ".jpeg": 5 * 1024 * 1024,
    ".png": 5 * 1024 * 1024,
    ".pdf": 10 * 1024 * 1024,
    ".docx": 10 * 1024 * 1024,
    ".xlsx": 10 * 1024 * 1024,
    ".mp4": 20 * 1024 * 1024,
}


def sanitized_display_name(name: str) -> str:
    leaf = PurePath(name.replace("\\", "/")).name
    leaf = re.sub(r"[\x00-\x1f\x7f]", "", leaf).strip(" .")[:180]
    if not leaf or leaf in {".", ".."}:
        raise InvalidUpload("invalid_filename")
    if re.search(r"\.(?:php\d?|phtml|html?|svg|js|exe|bat|cmd|sh)\.", leaf, flags=re.I):
        raise InvalidUpload("invalid_filename")
    return leaf


def _validate_image(data: bytes, extension: str) -> None:
    if extension in {".jpg", ".jpeg"} and not data.startswith(b"\xff\xd8\xff"):
        raise InvalidUpload("invalid_file")
    if extension == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise InvalidUpload("invalid_file")
    Image.MAX_IMAGE_PIXELS = 20_000_000
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format not in ({"JPEG"} if extension in {".jpg", ".jpeg"} else {"PNG"}):
                raise InvalidUpload("invalid_file")
            if image.width * image.height > 20_000_000 or max(image.size) > 10_000:
                raise InvalidUpload("image_dimensions_exceeded")
            image.verify()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise InvalidUpload("invalid_file") from exc


def _validate_pdf(data: bytes) -> None:
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
        raise InvalidUpload("invalid_file")
    try:
        reader = PdfReader(io.BytesIO(data), strict=True)
        if len(reader.pages) > 200 or reader.is_encrypted:
            raise InvalidUpload("invalid_file")
        root = reader.trailer["/Root"].get_object()
        if any(key in root for key in ("/OpenAction", "/AA", "/AcroForm")):
            raise InvalidUpload("active_pdf_content")
        names = root.get("/Names")
        if names and ("/JavaScript" in names or "/EmbeddedFiles" in names):
            raise InvalidUpload("active_pdf_content")
        for page in reader.pages:
            if "/AA" in page:
                raise InvalidUpload("active_pdf_content")
            for annotation in page.get("/Annots", []):
                obj = annotation.get_object()
                action = obj.get("/A")
                if action and action.get_object().get("/S") in {"/JavaScript", "/Launch", "/GoToR", "/SubmitForm"}:
                    raise InvalidUpload("active_pdf_content")
    except InvalidUpload:
        raise
    except Exception as exc:
        raise InvalidUpload("invalid_file") from exc


def _validate_office(data: bytes, extension: str) -> None:
    expected = "word/document.xml" if extension == ".docx" else "xl/workbook.xml"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > 500:
                raise InvalidUpload("invalid_office_file")
            total_uncompressed = sum(entry.file_size for entry in entries)
            if total_uncompressed > 50 * 1024 * 1024 or total_uncompressed / max(len(data), 1) > 100:
                raise InvalidUpload("archive_limits_exceeded")
            if archive.testzip() is not None:
                raise InvalidUpload("invalid_office_file")
            names = {entry.filename for entry in entries}
            if "[Content_Types].xml" not in names or expected not in names:
                raise InvalidUpload("invalid_office_file")
            for entry in entries:
                lowered = entry.filename.lower()
                if entry.flag_bits & 1 or "vbaproject" in lowered or "externallinks/" in lowered or "embeddings/" in lowered:
                    raise InvalidUpload("active_office_content")
                if lowered.endswith((".bin", ".xlsm", ".xltm", ".docm", ".dotm")):
                    raise InvalidUpload("active_office_content")
                if entry.filename.endswith(".rels"):
                    content = archive.read(entry)
                    if len(content) > 2 * 1024 * 1024:
                        raise InvalidUpload("archive_limits_exceeded")
                    root = ElementTree.fromstring(content)
                    if any(node.attrib.get("TargetMode", "").lower() == "external" for node in root.iter()):
                        raise InvalidUpload("external_relationship")
    except InvalidUpload:
        raise
    except (zipfile.BadZipFile, OSError, ElementTree.ParseError, RuntimeError) as exc:
        raise InvalidUpload("invalid_office_file") from exc


def _boxes(data: bytes) -> list[tuple[bytes, int, int]]:
    boxes = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise InvalidUpload("invalid_mp4")
        size, kind = struct.unpack(">I4s", data[offset : offset + 8])
        header_size = 8
        if size == 1:
            if len(data) - offset < 16:
                raise InvalidUpload("invalid_mp4")
            size = struct.unpack(">Q", data[offset + 8 : offset + 16])[0]
            header_size = 16
        elif size == 0:
            size = len(data) - offset
        if size < header_size or offset + size > len(data):
            raise InvalidUpload("invalid_mp4")
        boxes.append((kind, offset + header_size, offset + size))
        if len(boxes) > 4096:
            raise InvalidUpload("invalid_mp4")
        offset += size
    return boxes


def _validate_mp4(data: bytes) -> None:
    boxes = _boxes(data)
    if not boxes or boxes[0][0] != b"ftyp" or not any(box[0] == b"moov" for box in boxes) or not any(box[0] == b"mdat" for box in boxes):
        raise InvalidUpload("invalid_mp4")
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        raise InvalidUpload("video_validation_unavailable")
    try:
        result = subprocess.run(
            [ffprobe, "-v", "error", "-protocol_whitelist", "pipe,crypto,data", "-show_entries", "format=duration:stream=codec_type,width,height", "-of", "json", "pipe:0"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        if result.returncode != 0 or len(result.stdout) > 64 * 1024:
            raise InvalidUpload("invalid_mp4")
        detail = json.loads(result.stdout)
        streams = detail.get("streams", [])
        duration = float(detail.get("format", {}).get("duration", 0))
        videos = [stream for stream in streams if stream.get("codec_type") == "video"]
        if not videos or len(streams) > 4 or not 0 < duration <= 600:
            raise InvalidUpload("video_limits_exceeded")
        for stream in videos:
            if int(stream.get("width", 0)) > 1920 or int(stream.get("height", 0)) > 1080:
                raise InvalidUpload("video_limits_exceeded")
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidUpload("invalid_mp4") from exc


def validate_file(filename: str, content_type: str, data: bytes, max_total: int) -> ValidatedFile:
    display_name = sanitized_display_name(filename)
    extension = PurePath(display_name).suffix.lower()
    if extension not in MIME_BY_EXTENSION:
        raise InvalidUpload("unsupported_file_type")
    if len(data) > min(MAX_BYTES[extension], max_total):
        raise InvalidUpload("file_too_large")
    kind, allowed_mimes = MIME_BY_EXTENSION[extension]
    if content_type.lower().split(";", 1)[0].strip() not in allowed_mimes:
        raise InvalidUpload("mime_mismatch")
    if kind == "image":
        _validate_image(data, extension)
    elif kind == "pdf":
        _validate_pdf(data)
    elif kind in {"docx", "xlsx"}:
        _validate_office(data, extension)
    elif kind == "video":
        _validate_mp4(data)
    return ValidatedFile(kind=kind, mime_type=next(iter(allowed_mimes)), display_name=display_name, size=len(data))
