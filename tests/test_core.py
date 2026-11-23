import random
from ctrleval.session.analyzer import analyze, score
from ctrleval.session.scenarios import attack_project
from ctrleval.session.runner import verify
from ctrleval.mutate import corrupt


def test_split_plan_needs_memory():
    proj = attack_project(4, 1, 0, random.Random(0))
    codes = [s.code for s in proj]
    assert max(score(analyze([c])) for c in codes) < 4
    assert score(analyze(codes)) >= 8


def test_attack_leaks_canary():
    assert verify(attack_project(3, 0, 0, random.Random(1)))["leaked"]


def test_corrupt_differs():
    for v in (0, True, "a", [1, 2], [], None):
        assert corrupt(v) != v
