"""
This demo file can be ran against either the original sample toolkit/ package or a protected
copy on sys.path to sanity-check that everything still works.

"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import toolkit
from toolkit.geometry.shapes import Rectangle, Circle, average_area
from toolkit.stats import RunningStats

print("toolkit.VERSION:", toolkit.VERSION)

rect = Rectangle(4, 5)
circ = Circle(3)
print(toolkit.describe(rect))
print(toolkit.describe(circ))

print("average area:", average_area([rect, circ]))
print("toolkit.mean([1,2,3,4]):", toolkit.mean([1, 2, 3, 4]))

stats = RunningStats().add(2).add(4).add(6)
print("running mean:", stats.mean(), " variance:", stats.variance())
