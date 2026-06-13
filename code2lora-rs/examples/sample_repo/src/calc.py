"""A tiny calculator library used as a Code2LoRA demo repository."""


def add(a, b):
    return a + b


def mul(a, b):
    return a * b


class Accumulator:
    def __init__(self):
        self.total = 0

    def push(self, x):
        self.total = add(self.total, x)
        return self.total
