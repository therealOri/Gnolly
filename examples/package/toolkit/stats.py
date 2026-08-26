"""Basic stats helpers, imported by both toolkit/__init__.py and geometry/shapes.py."""

VERSION = "1.0.0"


def mean(values):
    values = list(values)
    if not values:
        return 0.0
    return sum(values) / len(values)


def variance(values):
    values = list(values)
    m = mean(values)
    return mean([(v - m) ** 2 for v in values])


class RunningStats:
    """A small stateful class -> exercises method calls on protected instances."""

    def __init__(self):
        self._values = []

    def add(self, value):
        self._values.append(value)
        return self

    def mean(self):
        return mean(self._values)

    def variance(self):
        return variance(self._values)
