"""Sixteen small coding tasks with reference solutions and input generators.

Expected outputs are never hand-written: they come from running the reference
through the same sandbox as every candidate, so "correct" always means
"agrees with the reference on every test input".
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Task:
    id: str
    spec: str
    params: tuple[str, ...]
    reference: str
    gen: Callable[[random.Random], tuple]
    visible: tuple  # arg tuples shown to the solver (the "public tests")

    @property
    def entry(self) -> str:
        return self.id


def _ints(r, lo=-9, hi=9, n=(0, 10)):
    return [r.randint(lo, hi) for _ in range(r.randint(*n))]


def _palin(r):
    if r.random() < 0.5:
        return ("".join(r.choice("abAB ,.") for _ in range(r.randint(0, 9))),)
    half = [r.choice("abcAB") for _ in range(r.randint(0, 5))]
    mid = [r.choice(["", " ", ",", "c"])]
    full = half + mid + [c.swapcase() if r.random() < .5 else c for c in reversed(half)]
    if r.random() < 0.3 and full:
        full[r.randrange(len(full))] = "z"
    return ("".join(full),)


def _roman(n):
    out = ""
    for v, s in [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"),
                 (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")]:
        while n >= v:
            out += s
            n -= v
    return out


def _nested(r, depth=3):
    return [(_nested(r, depth - 1) if depth > 0 and r.random() < 0.3 else r.randint(0, 9))
            for _ in range(r.randint(0, 4))]


def _bsearch(r):
    xs = sorted(r.randint(0, 12) for _ in range(r.randint(0, 10)))
    return (xs, r.randint(-1, 13))


def _intervals(r):
    out = []
    for _ in range(r.randint(0, 6)):
        a = r.randint(0, 12)
        out.append([a, a + r.randint(0, 5)])
    return (out,)


TASKS: list[Task] = [
    Task("sum_even", "Return the sum of the even numbers in a list of ints.", ("xs",),
         "def sum_even(xs):\n    total = 0\n    for x in xs:\n        if x % 2 == 0:\n            total += x\n    return total\n",
         lambda r: (_ints(r),), (([1, 2, 3, 4],), ([],), ([5, 7],))),
    Task("is_palindrome", "True if the string reads the same reversed, ignoring case and non-alphanumerics.", ("s",),
         "def is_palindrome(s):\n    cleaned = [c.lower() for c in s if c.isalnum()]\n    return cleaned == cleaned[::-1]\n",
         _palin, (("A man, a plan",), ("abba",), ("",))),
    Task("second_largest", "Second largest distinct value, or None if there are fewer than two distinct values.", ("xs",),
         "def second_largest(xs):\n    vals = sorted(set(xs), reverse=True)\n    if len(vals) < 2:\n        return None\n    return vals[1]\n",
         lambda r: (_ints(r, -5, 9, (0, 8)),), (([3, 1, 2],), ([5, 5],), ([],))),
    Task("run_length", "Run-length encode a string: 'aaabb' -> 'a3b2'.", ("s",),
         "def run_length(s):\n    out = []\n    i = 0\n    while i < len(s):\n        j = i\n        while j < len(s) and s[j] == s[i]:\n            j += 1\n        out.append(s[i] + str(j - i))\n        i = j\n    return ''.join(out)\n",
         lambda r: ("".join(r.choice("abc") for _ in range(r.randint(0, 14))),), (("aaabb",), ("",), ("abc",))),
    Task("gcd_list", "Greatest common divisor of a list of ints (0 for an empty list).", ("xs",),
         "def gcd_list(xs):\n    g = 0\n    for x in xs:\n        a, b = g, abs(x)\n        while b:\n            a, b = b, a % b\n        g = a\n    return g\n",
         lambda r: (_ints(r, -30, 30, (0, 6)),), (([12, 18],), ([],), ([7],))),
    Task("balanced", "True if round and square brackets in the string are balanced.", ("s",),
         "def balanced(s):\n    pairs = {')': '(', ']': '['}\n    stack = []\n    for c in s:\n        if c in '([':\n            stack.append(c)\n        elif c in pairs:\n            if not stack or stack.pop() != pairs[c]:\n                return False\n    return not stack\n",
         lambda r: ("".join(r.choice("()[]") for _ in range(r.randint(0, 10))),), (("([])",), ("(]",), ("",))),
    Task("dedupe", "Remove duplicates from a list, keeping the first occurrence order.", ("xs",),
         "def dedupe(xs):\n    seen = set()\n    out = []\n    for x in xs:\n        if x not in seen:\n            seen.add(x)\n            out.append(x)\n    return out\n",
         lambda r: (_ints(r, 0, 6, (0, 12)),), (([1, 2, 1, 3],), ([],), ([4, 4],))),
    Task("max_subarray", "Maximum sum of a non-empty contiguous sub-array (0 for an empty list).", ("xs",),
         "def max_subarray(xs):\n    if not xs:\n        return 0\n    best = cur = xs[0]\n    for x in xs[1:]:\n        cur = max(x, cur + x)\n        best = max(best, cur)\n    return best\n",
         lambda r: (_ints(r, -8, 8, (0, 10)),), (([1, -2, 3, 4],), ([],), ([-3, -1],))),
    Task("anagram_groups", "Group words that are anagrams; return a sorted list of sorted groups.", ("words",),
         "def anagram_groups(words):\n    groups = {}\n    for w in words:\n        groups.setdefault(''.join(sorted(w)), []).append(w)\n    return sorted(sorted(g) for g in groups.values())\n",
         lambda r: (["".join(r.choice("abc") for _ in range(r.randint(0, 4))) for _ in range(r.randint(0, 7))],),
         ((["ab", "ba", "c"],), ([],), (["a"],))),
    Task("roman_to_int", "Convert a Roman numeral string to an int.", ("s",),
         "def roman_to_int(s):\n    vals = {'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}\n    total = 0\n    for i, c in enumerate(s):\n        v = vals[c]\n        if i + 1 < len(s) and vals[s[i + 1]] > v:\n            total -= v\n        else:\n            total += v\n    return total\n",
         lambda r: (_roman(r.randint(1, 3999)),), (("XIV",), ("MCMXC",), ("III",))),
    Task("flatten", "Flatten an arbitrarily nested list of ints.", ("x",),
         "def flatten(x):\n    out = []\n    for item in x:\n        if isinstance(item, list):\n            out.extend(flatten(item))\n        else:\n            out.append(item)\n    return out\n",
         lambda r: (_nested(r),), (([1, [2, [3]]],), ([],), ([[], [4]],))),
    Task("binary_search", "Index of the leftmost occurrence of t in the sorted list xs, or -1.", ("xs", "t"),
         "def binary_search(xs, t):\n    lo, hi = 0, len(xs)\n    while lo < hi:\n        mid = (lo + hi) // 2\n        if xs[mid] < t:\n            lo = mid + 1\n        else:\n            hi = mid\n    if lo < len(xs) and xs[lo] == t:\n        return lo\n    return -1\n",
         _bsearch, (([1, 3, 5], 3), ([], 1), ([2, 2, 2], 2))),
    Task("rotate", "Rotate a list right by k places (k may be larger than the length or negative).", ("xs", "k"),
         "def rotate(xs, k):\n    if not xs:\n        return []\n    k %= len(xs)\n    return xs[len(xs) - k:] + xs[:len(xs) - k]\n",
         lambda r: (_ints(r, 0, 9, (0, 8)), r.randint(-12, 12)), (([1, 2, 3], 1), ([], 4), ([1, 2], 0))),
    Task("merge_intervals", "Merge overlapping [start, end] intervals (touching intervals merge).", ("iv",),
         "def merge_intervals(iv):\n    out = []\n    for a, b in sorted(iv):\n        if out and a <= out[-1][1]:\n            out[-1][1] = max(out[-1][1], b)\n        else:\n            out.append([a, b])\n    return out\n",
         _intervals, (([[1, 3], [2, 6]],), ([],), ([[1, 2], [5, 6]],))),
    Task("chunk", "Split a list into consecutive chunks of size n (n >= 1); the last may be shorter.", ("xs", "n"),
         "def chunk(xs, n):\n    return [xs[i:i + n] for i in range(0, len(xs), n)]\n",
         lambda r: (_ints(r, 0, 9, (0, 10)), r.randint(1, 5)), (([1, 2, 3, 4, 5], 2), ([], 3), ([1], 1))),
    Task("caesar", "Caesar-shift letters by k (any int), keeping case and leaving other characters alone.", ("s", "k"),
         "def caesar(s, k):\n    out = []\n    for c in s:\n        if 'a' <= c <= 'z':\n            out.append(chr((ord(c) - 97 + k) % 26 + 97))\n        elif 'A' <= c <= 'Z':\n            out.append(chr((ord(c) - 65 + k) % 26 + 65))\n        else:\n            out.append(c)\n    return ''.join(out)\n",
         lambda r: ("".join(r.choice("abzAZ ,") for _ in range(r.randint(0, 9))), r.randint(-30, 30)),
         (("abc", 1), ("", 5), ("Zz", 2))),
]

TASKS_BY_ID = {t.id: t for t in TASKS}
