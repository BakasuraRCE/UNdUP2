import sys
import types
from pathlib import Path

import pytest

import main


class FakeContent:
    """Simula el contenido de un nodo de recursos."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def tobytes(self) -> bytes:
        return self.data


class FakeNode:
    """Simula un ResourceNode de lief."""

    def __init__(
        self,
        data: bytes | None = None,
        childs: list[FakeNode] | None = None,
        has_name: bool = False,
    ) -> None:
        self.is_data = data is not None
        self.has_name = has_name
        self.childs = childs or []
        if data is not None:
            self.content = FakeContent(data)


# Fake lief module setup
fake_lief_pe = types.SimpleNamespace(
    ResourcesManager=types.SimpleNamespace(
        TYPE=types.SimpleNamespace(RCDATA='RCDATA'),
    ),
    ResourceNode=FakeNode,
)
fake_lief = types.SimpleNamespace(
    PE=fake_lief_pe,
    parse=lambda _data: None,
)
sys.modules.setdefault('lief', fake_lief)
sys.modules.setdefault('lief.PE', fake_lief_pe)


def test_resource_data_bytes_handles_empty_and_nested_nodes() -> None:
    # Nodo vacío (sin data, sin childs) retorna None
    assert main.resource_data_bytes(FakeNode()) is None

    # Nodo con data retorna los bytes
    assert main.resource_data_bytes(FakeNode(b'direct')) == b'direct'

    # Nodo anidado: busca recursivamente el primer nodo con data
    nested_data = FakeNode(
        childs=[
            FakeNode(),  # sin data
            FakeNode(childs=[FakeNode(b'module')]),  # data anidada
        ],
    )
    assert main.resource_data_bytes(nested_data) == b'module'

    # Retorna el primer match, no todos
    multiple = FakeNode(
        childs=[
            FakeNode(b'first'),
            FakeNode(b'second'),
        ],
    )
    assert main.resource_data_bytes(multiple) == b'first'


def test_make_dup2_file_skips_nodes_without_resource_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rcdata = FakeNode(
        childs=[
            FakeNode(b'plugin', has_name=True),  # skipped: has_name=True
            FakeNode(),  # skipped: no data
            FakeNode(childs=[FakeNode(b'\x04search')]),  # included: nested data
            FakeNode(b'\x01direct'),  # included: direct data
            FakeNode(b''),  # included: empty bytes
        ],
    )
    binary = types.SimpleNamespace(
        has_resources=True,
        resources_manager=types.SimpleNamespace(get_node_type=lambda _type: rcdata),
    )
    monkeypatch.setattr(main.lief, 'parse', lambda _data: binary)

    output = tmp_path / 'out.dUP2'
    main.make_dup2_file(b'dll', output)

    project = output.read_bytes()
    # 3 modules: nested \x04search, direct \x01direct, and empty b""
    # (plugin is skipped due to has_name=True, empty FakeNode() returns None)
    assert int.from_bytes(project[:4], byteorder='little') == 3
    assert b'\x04search' in project
    assert b'\x01direct' in project


def test_make_dup2_file_raises_on_invalid_dll(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(main.lief, 'parse', lambda _data: None)

    with pytest.raises(Exception, match='Could not parse dumped DLL'):
        main.make_dup2_file(b'invalid', tmp_path / 'out.dUP2')


def test_make_dup2_file_raises_on_no_resources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = types.SimpleNamespace(has_resources=False)
    monkeypatch.setattr(main.lief, 'parse', lambda _data: binary)

    with pytest.raises(Exception, match='not have resources'):
        main.make_dup2_file(b'dll', tmp_path / 'out.dUP2')


def test_make_dup2_file_raises_on_no_rcdata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = types.SimpleNamespace(
        has_resources=True,
        resources_manager=types.SimpleNamespace(get_node_type=lambda _type: None),
    )
    monkeypatch.setattr(main.lief, 'parse', lambda _data: binary)

    with pytest.raises(Exception, match='has no RCDATA resources'):
        main.make_dup2_file(b'dll', tmp_path / 'out.dUP2')
