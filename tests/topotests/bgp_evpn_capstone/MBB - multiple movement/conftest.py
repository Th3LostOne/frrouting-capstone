"""Give FRR's shell-based log helpers a test ID without spaces."""


def pytest_collection_modifyitems(items):
    for item in items:
        node = item
        while node is not None:
            if "MBB - multiple movement" in node.nodeid:
                node._nodeid = node.nodeid.replace(
                    "MBB - multiple movement", "mbb_multiple_movement"
                )
            node = node.parent
