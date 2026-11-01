"""Tests for the SAS derivation and rendering (design §7)."""

from __future__ import annotations

import pytest

from securesync.core.protocol import ProtocolError
from securesync.infrastructure.networking.handshake_sas import (
    BITS_PER_WORD,
    DEFAULT_WORD_COUNT,
    DIGIT_COUNT,
    MAX_DIGIT_COUNT,
    MAX_WORD_COUNT,
    WORDLIST_SIZE,
    SasError,
    entropy_bits,
    format_sas,
    sas_digits,
    sas_material,
    sas_words,
)
from securesync.infrastructure.networking.sas_wordlist import SAS_WORDS

#: Frozen ``t_final`` from the message-layer known-answer test.
T_FINAL = bytes.fromhex("6a990fd748d5c02415175ce9623e92c7410d25630e1d0458f7f8573f56921fe3")
EXPECTED_MATERIAL = "9c25e36663b3addadb74e10491aeea0ef475fa310903ffbe3b6e0c0e2d8b6f92"
EXPECTED_WORDS = ("order", "congress", "sunset", "shuffle")
EXPECTED_DIGITS = "10984850"


class TestWordlist:
    def test_has_exactly_2048_entries(self) -> None:
        assert len(SAS_WORDS) == WORDLIST_SIZE == 2048

    def test_entries_are_unique(self) -> None:
        assert len(set(SAS_WORDS)) == WORDLIST_SIZE

    def test_entries_are_sorted(self) -> None:
        # Sortedness is not required by the derivation, but it makes the table
        # reviewable and lets a reviewer diff it against its published source.
        assert list(SAS_WORDS) == sorted(SAS_WORDS)

    def test_entries_are_lowercase_ascii_letters(self) -> None:
        for word in SAS_WORDS:
            assert word.isascii() and word.isalpha() and word.islower(), word

    def test_entries_are_at_most_eight_characters(self) -> None:
        assert max(len(word) for word in SAS_WORDS) <= 8

    def test_first_four_letters_are_unique(self) -> None:
        # Lets a user type a prefix unambiguously when reading a SAS back.
        assert len({word[:4] for word in SAS_WORDS}) == WORDLIST_SIZE


class TestMaterial:
    def test_known_answer(self) -> None:
        assert sas_material(T_FINAL).hex() == EXPECTED_MATERIAL

    def test_is_a_sha256_digest(self) -> None:
        assert len(sas_material(T_FINAL)) == 32

    def test_is_deterministic(self) -> None:
        assert sas_material(T_FINAL) == sas_material(T_FINAL)

    def test_depends_on_the_transcript(self) -> None:
        assert sas_material(b"\x00" * 32) != sas_material(T_FINAL)

    def test_wrong_transcript_length_is_rejected(self) -> None:
        with pytest.raises(SasError):
            sas_material(b"\x00" * 31)
        with pytest.raises(SasError):
            sas_material(b"\x00" * 33)


class TestWords:
    def test_known_answer(self) -> None:
        assert sas_words(sas_material(T_FINAL)) == EXPECTED_WORDS

    def test_default_is_four_words(self) -> None:
        assert DEFAULT_WORD_COUNT == 4
        assert len(sas_words(sas_material(T_FINAL))) == 4

    def test_default_shows_44_bits(self) -> None:
        assert entropy_bits(DEFAULT_WORD_COUNT) == 44

    def test_words_come_from_the_list(self) -> None:
        for word in sas_words(sas_material(T_FINAL), count=8):
            assert word in SAS_WORDS

    def test_first_word_depends_only_on_the_leading_eleven_bits(self) -> None:
        # Two materials that agree on the first 11 bits must agree on word one,
        # regardless of everything after it.
        shared_prefix = 0b101_1010_1010 << (8 * 32 - BITS_PER_WORD)
        first = shared_prefix.to_bytes(32, "big")
        second = (shared_prefix | 0xFFFF).to_bytes(32, "big")
        assert first != second
        assert sas_words(first, count=1) == sas_words(second, count=1)

    def test_a_flipped_leading_bit_changes_the_first_word(self) -> None:
        material = sas_material(T_FINAL)
        flipped = bytes([material[0] ^ 0x80]) + material[1:]
        assert sas_words(flipped, count=1) != sas_words(material, count=1)

    def test_more_words_are_a_prefix_extension(self) -> None:
        material = sas_material(T_FINAL)
        assert sas_words(material, count=6)[:4] == sas_words(material, count=4)

    def test_word_count_out_of_range_is_rejected(self) -> None:
        material = sas_material(T_FINAL)
        for count in (0, -1, MAX_WORD_COUNT + 1):
            with pytest.raises(SasError):
                sas_words(material, count=count)

    def test_material_too_short_is_rejected(self) -> None:
        with pytest.raises(SasError):
            sas_words(b"\x00" * 4, count=4)

    def test_wordlist_of_the_wrong_size_is_rejected(self) -> None:
        with pytest.raises(SasError):
            sas_words(sas_material(T_FINAL), wordlist=("a", "b", "c"))


class TestDigits:
    def test_known_answer(self) -> None:
        assert sas_digits(sas_material(T_FINAL)) == EXPECTED_DIGITS

    def test_default_is_eight_digits(self) -> None:
        assert DIGIT_COUNT == 8
        rendered = sas_digits(sas_material(T_FINAL))
        assert len(rendered) == 8
        assert rendered.isdigit()

    def test_is_zero_padded(self) -> None:
        assert sas_digits(b"\x00" * 31 + b"\x01") == "00000001"

    def test_digit_count_out_of_range_is_rejected(self) -> None:
        material = sas_material(T_FINAL)
        for count in (0, -1, MAX_DIGIT_COUNT + 1):
            with pytest.raises(SasError):
                sas_digits(material, count=count)

    def test_empty_material_is_rejected(self) -> None:
        with pytest.raises(SasError):
            sas_digits(b"")


class TestFormatting:
    def test_known_answer(self) -> None:
        assert format_sas(EXPECTED_WORDS) == "order-congress-sunset-shuffle"

    def test_custom_separator(self) -> None:
        assert format_sas(("a", "b"), separator=" ") == "a b"

    def test_empty_word_sequence_is_rejected(self) -> None:
        with pytest.raises(SasError):
            format_sas(())


class TestErrors:
    def test_entropy_bits_rejects_bad_counts(self) -> None:
        for count in (0, MAX_WORD_COUNT + 1):
            with pytest.raises(SasError):
                entropy_bits(count)

    def test_every_error_is_a_protocol_error(self) -> None:
        assert issubclass(SasError, ProtocolError)
