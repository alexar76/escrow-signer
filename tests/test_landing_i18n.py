"""The landing must say the same things in five languages.

English deliberately does not live in the dictionary: it lives in the markup, so the document
a crawler reads is the document a reader sees and the English copy cannot drift from a
translation of itself. That makes key parity the only thing left to check — plus the handful of
claims that must survive translation, because a landing that drops the residual-risk paragraph
in four languages out of five is not a translation, it is a sales page.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

LANDING = Path(__file__).resolve().parents[1] / "docs" / "landing" / "index.html"
LANGS = ("ru", "es", "fr", "zh")


def _html() -> str:
    return LANDING.read_text(encoding="utf-8")


def _markup_keys(html: str) -> set:
    return set(re.findall(r'data-i18n="([A-Za-z0-9]+)"', html))


def _dict_keys(html: str, lang: str) -> set:
    block = re.search(r"\n  %s:\{(.*?)\n  \},\n" % lang, html, re.S)
    assert block, f"no dictionary for {lang}"
    # Keys can share a line, so scan the whole block rather than line starts.
    return set(re.findall(r'([A-Za-z0-9]+)\s*:\s*"', block.group(1)))


def test_the_landing_exists_and_is_one_self_contained_file():
    html = _html()
    assert html.lstrip().startswith("<!doctype html>")
    # No external anything: a landing that fetches a font or a script is a landing that breaks
    # behind a strict CSP, and every asset here is drawn rather than downloaded.
    for forbidden in ("<script src=", "@import", "cdn.", "googleapis", "unpkg", "jsdelivr"):
        assert forbidden not in html, forbidden


@pytest.mark.parametrize("lang", LANGS)
def test_every_language_covers_every_key(lang):
    html = _html()
    missing = sorted(_markup_keys(html) - _dict_keys(html, lang))
    assert not missing, (lang, missing)


@pytest.mark.parametrize("lang", LANGS)
def test_no_language_carries_a_key_the_markup_does_not_use(lang):
    html = _html()
    stale = sorted(_dict_keys(html, lang) - _markup_keys(html))
    assert not stale, (lang, stale)


def test_english_is_in_the_markup_not_in_a_dictionary():
    html = _html()
    assert re.search(r"\n  en:\{", html) is None, (
        "an `en` dictionary appeared — English must stay in the markup so the two cannot drift")
    assert 'data-i18n="lede"' in html


@pytest.mark.parametrize("lang", LANGS)
def test_the_residual_risk_survives_translation(lang):
    """The claim, in each language, that a compromised hub can still collect."""
    html = _html()
    block = re.search(r"\n  %s:\{(.*?)\n  \},\n" % lang, html, re.S).group(1)
    claims = {
        "ru": "может собрать деньги за невыполненную работу",
        "es": "seguir cobrando por trabajo no realizado",
        "fr": "encaisser un travail non rendu",
        "zh": "就未交付的工作收款",
    }
    assert claims[lang] in block, lang


def test_the_invariants_appear_untranslated():
    """Addresses and selectors are facts, not copy: they must be identical everywhere."""
    html = _html()
    for token in ("0xf7becd80", "0xBE0bBE44cceCfEb048dd53f601C37525a3D6C5f1",
                  "0x12Db8FAC81E5999D2f2087B79e38951571562CF2", "8453",
                  "debitChannel(bytes32,uint256,bytes32,uint256,bytes)"):
        assert token in html, token


def test_the_rule_ladder_matches_the_implementation():
    """Every rule the landing advertises must exist in the policy code, by name."""
    html = _html()
    advertised = set(re.findall(r'\["(R\d+)"', html))
    assert len(advertised) >= 15, advertised
    policy = (Path(__file__).resolve().parents[1] / "escrow_signer").glob("*.py")
    source = "\n".join(p.read_text(encoding="utf-8") for p in policy)
    missing = sorted(r for r in advertised if r not in source)
    assert not missing, f"the landing advertises rules the code does not name: {missing}"
