"""Markdown importer classification tests."""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood.importers.markdown import MarkdownDocument, build_memory_spec  # noqa: E402


def _doc(relative_path: str, body: str, frontmatter=None) -> MarkdownDocument:
    return MarkdownDocument(
        path=Path(relative_path),
        relative_path=relative_path,
        frontmatter=frontmatter or {},
        content=body,
    )


def test_secret_topic_filename_with_benign_body_stays_internal():
    spec = build_memory_spec(
        _doc(
            "memory/feedback_security_and_credentials.md",
            "# Credential governance\n\nRule 45 requires owner approval before rotating keys.",
        )
    )

    assert spec.classification == "internal"
    assert spec.pii is False


def test_real_secret_content_restricts_benign_filename():
    spec = build_memory_spec(
        _doc(
            "memory/project_release_notes.md",
            "# Release notes\n\nAccess key: AKIA1111111111111111",
        )
    )

    assert spec.classification == "restricted"
    assert spec.pii is True


def test_explicit_restricted_frontmatter_wins_with_benign_body():
    spec = build_memory_spec(
        _doc(
            "memory/project_public_topic.md",
            "# Public topic\n\nNo secret material here.",
            frontmatter={"classification": "restricted"},
        )
    )

    assert spec.classification == "restricted"


def test_placeholder_secret_examples_do_not_restrict():
    spec = build_memory_spec(
        _doc(
            "memory/project_secret_examples.md",
            "# Examples\n\nUse sk-test-abcdefghijklmnopqrstuvwxyz or AKIAIOSFODNN7EXAMPLE in docs.",
        )
    )

    assert spec.classification == "internal"
    assert spec.pii is False


def main():
    test_secret_topic_filename_with_benign_body_stays_internal()
    test_real_secret_content_restricts_benign_filename()
    test_explicit_restricted_frontmatter_wins_with_benign_body()
    test_placeholder_secret_examples_do_not_restrict()
    print("MARKDOWN IMPORT CLASSIFICATION TESTS PASSED")


if __name__ == "__main__":
    main()
