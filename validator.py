# validator.py
# Insight Shield — AI Output Validation
# Purpose : Quality gate for AI-generated translations. Checks structure,
#           forbidden words, and word count. FK grade is logged but NEVER
#           used as a rejection gate (thesis adviser approved this decision).
# Used by : groq_translator.py — after each provider response, before caching.

import logging

import textstat
import config

logger = logging.getLogger("insightshield.validator")


def validate_manager_translation(text: str) -> bool:
    """
    Check if a MANAGER translation meets all hard-rejection criteria.
    Returns True if valid, False if rejected.

    Hard-rejection rules (ALL must pass):
    1. "WHAT HAPPENED:" must be present
    2. "WHAT TO DO:" must be present
    3. Word count must be <= MAX_WORDS (100 since Round 2)
    4. No FORBIDDEN_WORD found (case-insensitive substring match) — managers
       must not see TCP/RDP/SMB/etc. technical jargon.
    """
    if not text or not isinstance(text, str):
        logger.warning("Validation REJECTED (manager): empty or non-string input")
        return False

    if "WHAT HAPPENED:" not in text:
        logger.warning("Validation REJECTED (manager): missing 'WHAT HAPPENED:' section")
        return False

    if "WHAT TO DO:" not in text:
        logger.warning("Validation REJECTED (manager): missing 'WHAT TO DO:' section")
        return False

    word_count = len(text.split())
    if word_count > config.MAX_WORDS:
        logger.warning(
            "Validation REJECTED (manager): word count %d exceeds limit %d",
            word_count, config.MAX_WORDS,
        )
        return False

    found = contains_forbidden_word(text)
    if found is not None:
        logger.warning("Validation REJECTED (manager): forbidden word found: '%s'", found)
        return False

    logger.info("Validation PASSED (manager): word_count=%d", word_count)
    return True


def validate_it_recommendation(text: str) -> bool:
    """
    Check if an IT-only "Recommended Investigation Steps" output is valid.

    Hard-rejection rules (ALL must pass):
    1. "INVESTIGATE:" section header present
    2. "CHECK:" section header present
    3. "MITIGATE:" section header present
    4. Word count <= IT_REC_MAX_WORDS (120)

    NO forbidden-word check — IT staff need TCP/RDP/SMB/etc. by definition.
    """
    if not text or not isinstance(text, str):
        logger.warning("Validation REJECTED (it_rec): empty or non-string input")
        return False

    for tag in ("INVESTIGATE:", "CHECK:", "MITIGATE:"):
        if tag not in text:
            logger.warning("Validation REJECTED (it_rec): missing '%s' section", tag)
            return False

    # IT_REC_MAX_WORDS, not the shared MAX_WORDS. The prompt asks for 100 words
    # and models routinely land at 103-104; against a hard 100 that rejected
    # Groq AND Gemini on the same alert, burned two live calls, and stored
    # AI_CHAIN_EXHAUSTED. The manager translation keeps the stricter 100.
    word_count = len(text.split())
    if word_count > config.IT_REC_MAX_WORDS:
        logger.warning(
            "Validation REJECTED (it_rec): word count %d exceeds limit %d",
            word_count, config.IT_REC_MAX_WORDS,
        )
        return False

    logger.info("Validation PASSED (it_rec): word_count=%d", word_count)
    return True




# Round 7 — executive-summary validator.
# The audit-report exec summary is read by both IT_ADMIN and Manager, so it
# follows the manager-translation forbidden-word rules (no jargon) but has
# its own length envelope: 2-3 paragraphs, 150-400 words. Below 150 the
# summary is too thin for a "Security Audit Report" header section; above
# 400 it overruns one page in print and dilutes the AI's signal.
EXEC_MIN_WORDS = 150
EXEC_MAX_WORDS = 400


def validate_exec_summary(text: str) -> bool:
    """Validate an audit-report executive summary.

    Hard-rejection rules (ALL must pass):
    1. Non-empty string.
    2. >= 2 paragraphs (separated by a blank line — \\n\\n).
    3. Word count in [EXEC_MIN_WORDS, EXEC_MAX_WORDS].
    4. No forbidden words — the manager reads this section too.
    """
    if not text or not isinstance(text, str):
        logger.warning("Validation REJECTED (exec_summary): empty or non-string input")
        return False

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if len(paragraphs) < 2:
        logger.warning(
            "Validation REJECTED (exec_summary): only %d paragraph(s) — need >= 2",
            len(paragraphs),
        )
        return False

    word_count = len(text.split())
    if word_count < EXEC_MIN_WORDS or word_count > EXEC_MAX_WORDS:
        logger.warning(
            "Validation REJECTED (exec_summary): word count %d outside [%d, %d]",
            word_count, EXEC_MIN_WORDS, EXEC_MAX_WORDS,
        )
        return False

    found = contains_forbidden_word(text)
    if found is not None:
        logger.warning("Validation REJECTED (exec_summary): forbidden word: '%s'", found)
        return False

    logger.info(
        "Validation PASSED (exec_summary): %d paragraphs, %d words",
        len(paragraphs), word_count,
    )
    return True


def contains_forbidden_word(text: str) -> str | None:
    """
    Check text for any word from the FORBIDDEN_WORDS list.
    Returns the first forbidden word found (for logging), or None if clean.
    Case-insensitive substring match.
    """
    text_lower = text.lower()
    for word in config.FORBIDDEN_WORDS:
        if word.lower() in text_lower:
            return word
    return None


def compute_fk_grade(text: str) -> float:
    """
    Compute Flesch-Kincaid Grade Level using textstat.
    Target: <= 6.0 (6th-grade reading level).

    This is a LOG METRIC only — never use this to reject output.
    Store the result in the fk_grade DB column for post-evaluation analysis.
    """
    if not text or not isinstance(text, str):
        return 0.0
    fk = textstat.flesch_kincaid_grade(text)
    logger.info("FK grade: %.1f (target: <= %.1f)", fk, config.FK_GRADE_TARGET)
    return round(fk, 1)
