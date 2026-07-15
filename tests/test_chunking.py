"""Phase 2 Area 3 chunking tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood.chunking import chunk_document  # noqa: E402


def test_chunk_document_preserves_offsets_ordinals_and_idempotence():
    text = (
        "# Alpha\n\n"
        "Alpha policy one two three four five.\n\n"
        "## Beta\n\n"
        "Beta policy six seven eight nine ten.\n\n"
        "Beta tail eleven twelve thirteen fourteen."
    )

    chunks = chunk_document(text, target_tokens=8, overlap=2)
    again = chunk_document(text, target_tokens=8, overlap=2)

    assert chunks == again
    assert [chunk.ordinal for chunk in chunks] == list(range(len(chunks)))
    assert all(text[chunk.char_start:chunk.char_end] == chunk.text for chunk in chunks)
    assert any("## Beta" in chunk.text for chunk in chunks)
    assert all(chunk.token_estimate > 0 for chunk in chunks)


def test_chunk_document_size_bounds_long_paragraph_with_overlap():
    text = "one two three four five six seven eight nine ten eleven twelve"

    chunks = chunk_document(text, target_tokens=5, overlap=2)

    assert [chunk.text for chunk in chunks] == [
        "one two three four five",
        "four five six seven eight nine ten",
        "nine ten eleven twelve",
    ]
    assert chunks[1].char_start < text.index("six")
    assert chunks[2].char_start < text.index("eleven")
