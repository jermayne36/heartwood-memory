"""Compatibility commitments for audit rows written by historical schemas.

These commitments do not rewrite or reinterpret stored audit rows. They bind
the display columns that the legacy body schema did not include, while the
ordinary chain hash continues to bind the original body, timestamp, and
predecessor.
"""
from __future__ import annotations

import hashlib
import json


_LEGACY_CLASSIFY_BODY_KEYS = frozenset(
    {"from", "operation", "source_ids_json", "task_id", "to"}
)

# The 2026-07-01 classification migration predates display/body binding. Each
# entry is seq: (row_hash, sha256(canonical displayed columns)). Keeping only
# commitments avoids publishing the target identifiers while making any later
# edit to tenant/principal/action/target detectable.
_DISPLAY_BINDING_COMMITMENTS = {
    "chain_530c8ac617451f376eaeb1dbd49e5a21": {
        13840: ("8cd8e5a610695f7c78f48cf51dda7caa7b2991ab90612d2ff78adfb57a198822", "7faa7b5b5c34b3ef2f81850325fef1f47a7c73e1c8c988c3c35829c700e9674e"),
        13841: ("a1af8292b0336fdde28b328f7fe4ec1ede4dd1528823276045eeb96a0c030bf7", "bbe47671c532e117a2ef8e8d776022df9de7792ae99d61d1d6c0ab587f49db62"),
        13842: ("6ae5aecb835dea4fca9f620603620b0526834ff39687846bc528722652734fc2", "5ac9517e33f4fca3f0c6921818bed39dbaf8e51312df7a9bb0ab7c2c30af6b72"),
        13843: ("c6c0811c35a6ebf6a7891cd00bced1ca67eb0c309c310b98d45b1d2398560c33", "15adeaf0e494c5f0b99c0f7044fc1223610a4ad095685dc15ec1affce919d4b5"),
        13844: ("58c24f1932f0de01da451569dade52932232ef7b7efe012e8f546f1879f05952", "670239d7b132486192a199c31c46f3829204436f5795eb375c423d746e262736"),
        13845: ("fc2612def1950cfef80d353a20804e38077cf23f3cb07e77cbed4d770ce01503", "b3710ad2d875adc61b545a611b293cf6c50ebcfbdf4faa3811513b296cc3eaca"),
        13846: ("364fcab39c521075a3972450e498b53c12904e385b38d38fe4cde670ec89eff4", "415e5f9bba5f60ad4ed574827465020e71646cab8db99ca01144ef4ef64eff5b"),
        13847: ("50749ce664726dceceefc265b636564b4d2a67a762a3c4b58706c9cc3cff40a5", "1d319d2907a2c30609a8356b91534c6bc7b263d87ec3c02d69fc269c932e215b"),
        13848: ("ca7a67b7caf268e3ade634d73888109d59850dc4ba458012019a69c46c93d4f1", "22a530b55e1abd57d0a6476622bf14ae4a1aa4ee72180ae9722ba1937041be39"),
        13849: ("04eec636bdb8ec4b3bfef99f0b108ed878462fbecab2f44827b0b3486e84cbfa", "cfec26df23e36d7568698a071c19a9da4b24d8df3df4105429438ccb7e0077e6"),
        13850: ("fa641737b2902c6add87a2785ccbf227e356af456aca6a059c5531de8ea856f7", "0c132e2747b0336b872e675f1d325f2db977893d1151cf7def38690492e11650"),
        13851: ("b57f622605f55ce955728f41e852845d52065705a3ce9e113da1dcdff8ecf919", "b0d4b64325ddeef41ab9d657a3333b284403079f47403f7cd5362fabbc75dfbc"),
        13852: ("d056b3de987ba7f166c75f4584127379b8b7013159e6c6223368eef8dd27eafb", "702caf804a328b884ae6ba0f87de20ec5b692984c4a208bed4c3b4b36b9acad5"),
        13853: ("007f731e09abf3bdc47af96f69342ff62a271f94cb5e634259ce7d3bdff380de", "ce39a1fb4c7716368b994ab3cc83c213a723fee8bd536557734916f0af3f8216"),
        13854: ("40d22ec7eba4908e0b2e4105155946e97834efe8851b38268d376c0727a74043", "e75f16be3cbd1705c523e3ad25ce5ac8f755da96a19077f371bc9f8cd19cb5a9"),
        13855: ("0e3b8121a6d95ee1c4c47c4a48b3aa0c88378deb590526d3cdc9108c6096db94", "159bad7915825adf372ea15988d0c81507f146371b6525a460cf7bb89e010b76"),
        13856: ("f64cddebabe52f02d51a4240c9993ad036416e7831b47b580863b5ed579a316d", "3e6204de7ab356494bd24601cd941429635f2043b20191f6242c1cd49d0ca42c"),
        13857: ("d85e9707934b68d149172f17c1fbade18e18a7615798d2a1c2c485608a1e7a72", "dd364bd45cd49423fbbef6bc3ea75ceaca2b5cc6c2a35ec80f044f53e9e94bc3"),
        13858: ("f6dc6e4ae6a72062be07a8a52177cb3de3afe0c87cbe08db1e16d17ef566997c", "cf5bc21d20f696676253b93102624d350960a1bcd118150a66a7be7a34c55cfb"),
        13859: ("c1c7a2c5b6cb4d2f45b5adaa0c732fa27f9e01ecf86f24ddd8db3564a2ee3e73", "bebd10171b2aae490fa634f290f2f77bb9c56252ff50c10e48ae9b52c021c09d"),
        13860: ("673d6475ae59b80edeff938c01e8f6086c897bfcb1057582463dd3e08a0d6285", "771dd84e9a934217f3836408ac8e2fd423adf9482e0e7171498eda03ad08ac9e"),
        13861: ("2899dcdd9d3ba2edfd3fb50a3a8ccf51c1b58dff7965f2a37616e7904c2bd9eb", "3a8b99583c0b1604c0d73d826676a5dd3b3e1c1269bcaf9e386f9c35e22aa6a2"),
        13862: ("8629002b818994e6cd01b2ed93cc5b9ae5fae32dfe381a2774000d5bd55e0df2", "4c257d0770fa2897c12d28eb764c70d60108ff5c8fb17b7e1924fe5ff61c25ed"),
        13863: ("a048e993ddc75cea149c03e769b07777befba6edbc72ec662b751f36742d30fd", "ed7edfbe3930272d8f37982619db451a313433c229c9811e36bcd9428ddc73fa"),
        13864: ("d67bbef77b2f83a5285a92b0fb4d9b02d6608f1448dcc825ced3e0c37fd035b7", "99f6ec9a0efb35282ea85b0b19816bd456c0f90044f5dbfe4776294db7fe2f73"),
        13865: ("1027d94a9e063a32e6c800b4b989723f852f3fdad198091a517e6b37f29b7fbe", "f69c1332bd8a2f870066ac4c3b64b348ed9899e06f7c3c7f9b7af41a9223efb8"),
        13866: ("6e7e5dbf61f2343c059fc1f02a9da2cdcf0206a3044c3063851905e85ef5671d", "d12bc35148c52e854520caeb0a28578782978b1e8ec9e63f692d4ad6ed750f36"),
        13867: ("07ce8041bfc3a41921cc4fcfa089efc1f4762bd0639b50b10968bfaa5a15bf77", "ee4e97415554a0e7ce87f93e2abaacb74c761d4fb13245e55d88dc6f5f3afcac"),
        13868: ("a95e31a9b7dd89d1eceea3720fcb9aefa3bfbdf70e4ad4442dcef1f443420e3d", "50861cbf25010f2792928aa08214bed5b218292790a3e62c1141e47b6ec4b4f5"),
        13869: ("1a65bbf014c6ed5ecf3397d4a06221be2a8dbec04ec25bb05cacb8d910c36b61", "1d0917014061d5e68cff4d68cb04633c2227dc2c1ff8cc2b03e677e9564461c2"),
        13870: ("962e6cf2da1af2944339176f33ebeaa1470a5817502c68927201e94971613bc9", "bae8e579997ad1e4629fa4b757e9a3a6e45e7db7df52544bfdf112d2303746cc"),
    }
}


def legacy_display_binding_matches(*, chain_id: str | None, row: dict, payload: dict) -> bool:
    """Return true only for an exactly committed legacy classify row."""
    if chain_id is None or set(payload) != _LEGACY_CLASSIFY_BODY_KEYS:
        return False
    if payload.get("operation") != "classification_update":
        return False
    try:
        expected_row_hash, expected_display_hash = _DISPLAY_BINDING_COMMITMENTS[
            chain_id
        ][int(row["seq"])]
    except (KeyError, TypeError, ValueError):
        return False
    if row.get("row_hash") != expected_row_hash:
        return False
    displayed = {key: row.get(key) for key in ("tenant", "principal", "action", "target")}
    actual_display_hash = hashlib.sha256(
        json.dumps(displayed, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return actual_display_hash == expected_display_hash
