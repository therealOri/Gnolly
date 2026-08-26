"""
Shapes, defined two directories down from the package root -> demonstrates
relative imports that reach back up past the immediate parent package
(`from ..stats import mean`).
"""
from ..stats import mean


class Rectangle:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def area(self):
        return self.width * self.height

    def perimeter(self):
        return 2 * (self.width + self.height)


class Circle:
    PI = 3.14159265358979

    def __init__(self, radius):
        self.radius = radius

    def area(self):
        return self.PI * self.radius ** 2

    def circumference(self):
        return 2 * self.PI * self.radius


def average_area(shapes):
    """Uses stats.mean() across a list of protected-class instances."""
    return mean(s.area() for s in shapes)
