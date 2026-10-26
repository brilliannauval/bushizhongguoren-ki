from __future__ import annotations

from io import BytesIO
import zipfile

from pypdf import PdfWriter
import pytest
from PIL import Image

from securebox.config import _validate_public_origin
from securebox.validation import InvalidUpload, validate_file


def _image_bytes(image_format: str) -> bytes:
    stream = BytesIO()
    Image.new("RGB", (2, 2), (1, 2, 3)).save(stream, format=image_format)
    return stream.getvalue()


def _office_bytes(document_path: str, relationship: bytes | None = None) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>")
        archive.writestr(document_path, "<document/>")
        if relationship is not None:
            archive.writestr("word/_rels/document.xml.rels", relationship)
    return stream.getvalue()


def _pdf_bytes() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    stream = BytesIO()
    writer.write(stream)
    return stream.getvalue()


@pytest.mark.parametrize(
    ("filename", "mime", "data", "kind"),
    [
        ("card.jpg", "image/jpeg", _image_bytes("JPEG"), "image"),
        ("card.png", "image/png", _image_bytes("PNG"), "image"),
        ("record.pdf", "application/pdf", _pdf_bytes(), "pdf"),
        (
            "letter.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            _office_bytes("word/document.xml"),
            "docx",
        ),
        (
            "sheet.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            _office_bytes("xl/workbook.xml"),
            "xlsx",
        ),
    ],
)
def test_supported_non_video_files_validate(filename, mime, data, kind):
    result = validate_file(filename, mime, data, 20 * 1024 * 1024)
    assert result.kind == kind
    assert result.display_name == filename
    assert result.size == len(data)


def test_filename_is_reduced_to_safe_leaf_and_active_double_extensions_are_rejected():
    result = validate_file("../../identity.png", "image/png", _image_bytes("PNG"), 20 * 1024 * 1024)
    assert result.display_name == "identity.png"
    with pytest.raises(InvalidUpload) as error:
        validate_file("../../payload.php.png", "image/png", _image_bytes("PNG"), 20 * 1024 * 1024)
    assert error.value.code == "invalid_filename"


@pytest.mark.parametrize(
    ("filename", "mime", "data", "maximum", "code"),
    [
        ("image.svg", "image/svg+xml", b"<svg/>", 100, "unsupported_file_type"),
        ("image.png", "image/jpeg", _image_bytes("PNG"), 20 * 1024 * 1024, "mime_mismatch"),
        ("image.png", "image/png", b"not an image", 20 * 1024 * 1024, "invalid_file"),
        ("image.png", "image/png", _image_bytes("PNG"), 1, "file_too_large"),
        ("record.pdf", "application/pdf", b"%PDF-garbage", 20 * 1024 * 1024, "invalid_file"),
        (
            "letter.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            b"not a zip file",
            20 * 1024 * 1024,
            "invalid_office_file",
        ),
        ("movie.mp4", "video/mp4", b"not an mp4", 20 * 1024 * 1024, "invalid_mp4"),
    ],
)
def test_rejects_invalid_or_oversized_inputs(filename, mime, data, maximum, code):
    with pytest.raises(InvalidUpload) as error:
        validate_file(filename, mime, data, maximum)
    assert error.value.code == code


def test_office_external_relationship_is_rejected():
    external = (
        b"<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>"
        b"<Relationship TargetMode='External' Target='https://example.invalid/' Type='x' Id='rId1'/>"
        b"</Relationships>"
    )
    with pytest.raises(InvalidUpload) as error:
        validate_file(
            "letter.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            _office_bytes("word/document.xml", external),
            20 * 1024 * 1024,
        )
    assert error.value.code == "external_relationship"


def test_production_public_origin_is_fixed_and_https_only():
    assert _validate_public_origin("https://securebox.example", development=False) == "https://securebox.example"
    with pytest.raises(RuntimeError, match="PUBLIC_ORIGIN must be configured"):
        _validate_public_origin(None, development=False)
    with pytest.raises(RuntimeError, match="only the public scheme"):
        _validate_public_origin("https://securebox.example/path", development=False)
    with pytest.raises(RuntimeError, match="only the public scheme"):
        _validate_public_origin("http://securebox.example", development=False)
