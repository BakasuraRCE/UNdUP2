import sys
import types


fake_lief = types.SimpleNamespace(
    PE=types.SimpleNamespace(
        ResourcesManager=types.SimpleNamespace(
            TYPE=types.SimpleNamespace(RCDATA="RCDATA"),
        ),
    ),
    parse=lambda _data: None,
)
sys.modules.setdefault("lief", fake_lief)

import main


class FakeContent:
    def __init__(self, data: bytes):
        self.data = data

    def tobytes(self) -> bytes:
        return self.data


class FakeNode:
    def __init__(
        self,
        data: bytes | None = None,
        childs: list["FakeNode"] | None = None,
        is_data: bool = False,
        has_name: bool = False,
    ):
        self.is_data = is_data
        self.has_name = has_name
        self.childs = childs or []
        if data is not None:
            self.content = FakeContent(data)


def test_resource_data_bytes_handles_empty_and_nested_nodes():
    assert main.resource_data_bytes(FakeNode()) is None

    nested_data = FakeNode(
        childs=[
            FakeNode(),
            FakeNode(childs=[FakeNode(b"module", is_data=True)]),
        ],
    )

    assert main.resource_data_bytes(nested_data) == b"module"


def test_make_dup2_file_skips_nodes_without_resource_data(monkeypatch, tmp_path):
    rcdata = FakeNode(
        childs=[
            FakeNode(b"plugin", is_data=True, has_name=True),
            FakeNode(),
            FakeNode(childs=[FakeNode(b"\x04search", is_data=True)]),
            FakeNode(b"\x01direct", is_data=True),
            FakeNode(b"", is_data=True),
        ],
    )
    binary = types.SimpleNamespace(
        has_resources=True,
        resources_manager=types.SimpleNamespace(get_node_type=lambda _type: rcdata),
    )
    monkeypatch.setattr(main.lief, "parse", lambda _data: binary)

    output = tmp_path / "out.dUP2"
    main.make_dup2_file(b"dll", output)

    project = output.read_bytes()
    assert int.from_bytes(project[:4], byteorder="little") == 3
    assert b"\x04search" in project
    assert b"\x01direct" in project
