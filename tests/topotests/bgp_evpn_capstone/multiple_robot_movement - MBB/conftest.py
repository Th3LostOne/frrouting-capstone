"""Give FRR's shell-based log helpers a test ID without spaces."""


def pytest_collection_modifyitems(items):
    for item in items:
        node = item
        while node is not None:
            if "multiple_robot_movement - MBB" in node.nodeid:
                node._nodeid = node.nodeid.replace(
                    "multiple_robot_movement - MBB", "mbb_multiple_movement"
                )
            node = node.parent
