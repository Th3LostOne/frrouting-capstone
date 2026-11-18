"""Keep spaces in the folder name out of FRR's shell-based temporary paths."""


def pytest_collection_modifyitems(items):
    for item in items:
        node = item
        while node is not None:
            if "multiple_robot_movement - BBM" in node.nodeid:
                node._nodeid = node.nodeid.replace(
                    "multiple_robot_movement - BBM", "bbm_multiple_robot_movement")
            node = node.parent
