#!/usr/bin/env python3
"""Pure-Python verification of the slot layout used by both FHE algorithms."""

from __future__ import annotations

from typing import Iterable, List

INPUT = list(range(1, 17))
KERNEL = [1, 2, 3, 4, 5, 6, 7, 8, 9]
OUTPUT_SLOTS = [0, 1, 4, 5]


def rotate_left(values: List[int], amount: int) -> List[int]:
    amount %= len(values)
    return values[amount:] + values[:amount]


def multiply(values: Iterable[int], mask: Iterable[int]) -> List[int]:
    return [left * right for left, right in zip(values, mask)]


def add(*vectors: Iterable[int]) -> List[int]:
    return [sum(items) for items in zip(*vectors)]


def mask(active: Iterable[int], value: int) -> List[int]:
    result = [0] * 16
    for index in active:
        result[index] = value
    return result


def naive() -> List[int]:
    terms = []
    for kernel_row in range(3):
        for kernel_col in range(3):
            offset = 4 * kernel_row + kernel_col
            shifted = rotate_left(INPUT, offset)
            terms.append(
                multiply(
                    shifted,
                    mask(OUTPUT_SLOTS, KERNEL[3 * kernel_row + kernel_col]),
                )
            )
    return add(*terms)


def optimized() -> List[int]:
    horizontal = [INPUT, rotate_left(INPUT, 1), rotate_left(INPUT, 2)]
    rows = []
    for kernel_row in range(3):
        base = 4 * kernel_row
        active = [base, base + 1, base + 4, base + 5]
        row_terms = []
        for kernel_col in range(3):
            row_terms.append(
                multiply(
                    horizontal[kernel_col],
                    mask(active, KERNEL[3 * kernel_row + kernel_col]),
                )
            )
        rows.append(add(*row_terms))
    return add(rows[0], rotate_left(rows[1], 4), rotate_left(rows[2], 8))


def main() -> None:
    expected = [348, 393, 0, 0, 528, 573, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    naive_result = naive()
    optimized_result = optimized()
    assert naive_result == expected
    assert optimized_result == expected
    print("naive:   ", naive_result)
    print("optimized:", optimized_result)
    print("reference verification passed")


if __name__ == "__main__":
    main()
