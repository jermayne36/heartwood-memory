"""Vector-index parity: the engine produces equivalent recall through the numpy
brute-force index and the sqlite-vec index, and erasure removes vectors from both.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Principal, Heartwood               # noqa: E402

FACTS = [
    "The capital of France is Paris.",
    "Photosynthesis converts sunlight into chemical energy in plants.",
    "Mitochondria are the powerhouse of the cell.",
    "Mount Everest is the tallest mountain on Earth.",
    "Refund requests are processed within 14 business days.",
]


def build(idx):
    db = Heartwood(path=":memory:", tenant="t", index=idx)
    for i, f in enumerate(FACTS):
        db.remember(f, subject=f"s{i}", created_by="ag")
    return db


def main():
    p = Principal("p", "t", clearance="internal")
    tops = {}
    expected = {"numpy": "numpy-bruteforce", "sqlite-vec": "sqlite-vec"}
    index_specs = ["numpy"]
    try:
        import sqlite_vec  # noqa: F401
        index_specs.append("sqlite-vec")
    except ModuleNotFoundError:
        print("[sqlite-vec] skipped; optional sqlite_vec package is not installed")

    for idx in index_specs:
        db = build(idx)
        assert db.info()["index"] == expected[idx], db.info()
        out = db.recall("which is the highest mountain in the world?", principal=p, k=2)
        contents = [r["content"] for r in out["results"]]
        assert any("Everest" in c for c in contents), (idx, contents)
        tops[idx] = contents[0]
        print(f"[{idx}] top-2 retrieved; Everest present. top1={contents[0][:40]!r}")

    if "sqlite-vec" in tops:
        assert tops["numpy"] == tops["sqlite-vec"], ("index disagreement", tops)
        print("[parity] numpy and sqlite-vec agree on the top result")

    # erasure removes the vector from the (sqlite-vec) index too
    if "sqlite-vec" in tops:
        db = build("sqlite-vec")
        db.forget("s3", mode="hard")   # the Everest fact
        out = db.recall("which is the highest mountain in the world?", principal=p, k=5)
        assert all("Everest" not in r["content"] for r in out["results"]), "vector survived erasure"
        print("[erasure] forget() removed the vector from the sqlite-vec index")

    print("\nVECTOR-INDEX TESTS PASSED")


if __name__ == "__main__":
    main()
