"""
A sample script to use as a protection target.
Contains classes, functions, string constants, integers, and logic.
"""

SECRET_VALUE = 42
GREETING = "Hello from a protected script!"


class Calculator:
    def __init__(self, base=0):
        self.base = base
        self._history = []

    def add(self, n):
        result = self.base + n
        self._history.append(("add", n, result))
        return result

    def multiply(self, n):
        result = self.base * n
        self._history.append(("multiply", n, result))
        return result

    def history(self):
        return list(self._history)


def fibonacci(n):
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b


def greet(name):
    msg = f"Hello, {name}! The answer is {SECRET_VALUE}."
    return msg


if __name__ == "__main__":
    print(GREETING)

    calc = Calculator(base=10)
    print("10 + 5 =", calc.add(5))
    print("10 * 3 =", calc.multiply(3))
    print("History:", calc.history())

    print("fibonacci(10) =", fibonacci(10))
    print(greet("World"))
