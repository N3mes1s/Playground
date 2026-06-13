from src.calc import add, mul, Accumulator


def test_add():
    assert add(2, 3) == 5


def test_mul():
    assert mul(4, 5) == 20


def test_accumulator():
    acc = Accumulator()
    acc.push(10)
    assert acc.push(5) == 15
