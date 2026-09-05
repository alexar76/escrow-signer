"""Five-language documentation parity, and the facts that must appear in every language.

A translation that quietly drops the residual-risk paragraph, or the sentence saying this key
is also the payee, is worse than no translation: it reads as complete while omitting the two
things an operator most needs to know. So the test checks for the *claims*, not the word count.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = {
    "en": ROOT / "README.md",
    "ru": ROOT / "docs" / "README.ru.md",
    "es": ROOT / "docs" / "README.es.md",
    "fr": ROOT / "docs" / "README.fr.md",
    "zh": ROOT / "docs" / "README.zh.md",
}

# Facts that are identical in every language because they are addresses, selectors and code.
INVARIANTS = (
    "0xBE0bBE44cceCfEb048dd53f601C37525a3D6C5f1",   # the signing address
    "0x12Db8FAC81E5999D2f2087B79e38951571562CF2",   # the pinned escrow
    "0xf7becd80",                                    # the only allowed selector
    "debitChannel(bytes32,uint256,bytes32,uint256,bytes)",
    "AIMarketEscrow.authorizedHubs",
    "AIMARKET_ESCROW_SUBMIT_STRATEGY=external",
    "i-understand-this-moves-funds",
    "settleChannel",
    "unlimited",
    "SIGNER_CAP_FEE_WEI_24H",
)


@pytest.mark.parametrize("lang", sorted(DOCS))
def test_every_language_exists_and_carries_the_invariants(lang):
    path = DOCS[lang]
    assert path.is_file(), f"{lang} documentation is missing"
    text = path.read_text(encoding="utf-8")
    for token in INVARIANTS:
        assert token in text, (lang, token)


@pytest.mark.parametrize("lang", sorted(DOCS))
def test_every_language_links_to_all_the_others(lang):
    text = DOCS[lang].read_text(encoding="utf-8")
    for other in ("README.ru.md", "README.es.md", "README.fr.md", "README.zh.md"):
        assert other in text, (lang, other)
    assert "README.md" in text, lang


def test_localized_docs_use_the_ecosystem_glossary():
    """docs/localization-glossary.md is the source of truth for these terms."""
    # Stems, not full forms: Russian and French inflect, so demanding the nominative
    # "платёжный канал" would force stilted prose to satisfy a test. The stem still proves the
    # glossary term was used rather than an invented synonym.
    required = {
        "ru": ("эскроу", "платёжн", "канал", "хаб"),
        "es": ("depósito en garantía", "canal de pago", "hub"),
        "fr": ("séquestre", "canal de paiement", "hub"),
        "zh": ("托管", "支付通道", "枢纽"),
    }
    for lang, terms in required.items():
        text = re.sub(r"\s+", " ", DOCS[lang].read_text(encoding="utf-8")).casefold()
        missing = [t for t in terms if t.casefold() not in text]
        assert not missing, (lang, missing)


@pytest.mark.parametrize("lang", sorted(DOCS))
def test_the_residual_risk_is_stated_in_every_language(lang):
    """The one thing a signer cannot fix must not be lost in translation."""
    # Collapse whitespace first: these files are hard-wrapped, so a claim legitimately
    # straddles a newline and a naive substring check fails on the English original.
    text = re.sub(r"\s+", " ", DOCS[lang].read_text(encoding="utf-8")).casefold()
    claims = {
        "en": "can still collect",
        "ru": "может собрать деньги за невыполненную работу",
        "es": "seguir cobrando por trabajo no realizado",
        "fr": "encaisser un travail non rendu",
        "zh": "就未交付的工作收款",
    }
    assert claims[lang].casefold() in text, lang


@pytest.mark.parametrize("lang", sorted(DOCS))
def test_the_key_is_also_the_payee_is_stated_in_every_language(lang):
    """Revenue lands on the hot key, not the treasury. Every operator has to read this."""
    text = DOCS[lang].read_text(encoding="utf-8")
    assert "settleChannel" in text and ("ch.hub" in text or "`ch.hub`" in text), lang


def test_the_readme_carries_the_badge_block_and_the_landing_link():
    text = DOCS["en"].read_text(encoding="utf-8")
    assert "<!-- aicom-readme-badges -->" in text
    assert "<!-- /aicom-readme-badges -->" in text
    assert "alexar76.github.io/escrow-signer" in text
    assert re.search(r"license-MIT|License:\s*MIT", text, re.I), "no licence badge"


def test_security_document_matches_the_implementation():
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for token in ("0xf7becd80", "292-byte", "R1–R26", "3xx", "digest16"):
        assert token in security, token
    # The claim in SECURITY.md that the selector is derived must remain true in the code.
    calldata = (ROOT / "escrow_signer" / "calldata.py").read_text(encoding="utf-8")
    assert "DEBIT_SELECTOR = selector(DEBIT_SIG)" in calldata
    assert '"0xf7becd80"' not in calldata, (
        "the selector is hardcoded again — SECURITY.md promises it is derived")
