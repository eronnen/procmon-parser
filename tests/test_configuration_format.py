import pytest
from procmon_parser import loads_configuration, dumps_configuration
from procmon_parser.configuration import Rule
from procmon_parser.consts import Column, RuleRelation, RuleAction


def test_parse_built_configuration_sanity():
    config = {
        "SymbolPath": "",
        "DbgHelpPath": "C:\\Windows\\help.dll",
        "FilterRules": [
            Rule('Path', 'contains', '1337', True),
            Rule('pid', 'is_not', '1338', True),
            Rule('Event_class', 'is', 'Profiling', False),
            Rule('Path', 'ends_with', '$Mft', False),
        ],
    }

    raw_config = dumps_configuration(config)
    parsed_raw_config = loads_configuration(raw_config)
    assert config == parsed_raw_config, "Parsed Built configuration is not equal to the original configuration"


def test_build_nonexistent_config_option():
    config = {
        u"FilterRules2": b"datadatadatadatadatadatadatadata"
    }

    raw_config = dumps_configuration(config)
    parsed_raw_config = loads_configuration(raw_config)
    assert config == parsed_raw_config, "Parsed Built configuration is not equal to the original configuration"


def test_build_mistyped_rule():
    config = {
        u"FilterRules": [
            Rule('Path', 'contains', '1337', True),
            Rule('pid', 'is_not', '1338', True),
            Rule('Event_class', 'is', 'Profiling', False),
            u"SomeString",
        ]
    }
    with pytest.raises(AttributeError):
        _ = dumps_configuration(config)

    with pytest.raises(TypeError):
        _ = Rule('Path', 'ends_with', 12345, False)


def test_build_mistyped_path_config_option():
    config = {
        "SymbolPath": [
            Rule('Path', 'contains', '1337', True),
            Rule('pid', 'is_not', '1338', True),
            Rule('Event_class', 'is', 'Profiling', False),
            Rule('Path', 'ends_with', '$Mft', False),
        ]
    }
    with pytest.raises(TypeError):
        _ = dumps_configuration(config)


def test_rule_equals():
    r1 = Rule('Path', 'contains', '1337', True)
    r2 = Rule('Path', 'contains', u'1337', True)
    assert r1 == r2

    r3 = Rule('Path', 'contains', u'1337', False)
    assert not r1 == r3
    assert r1 != r3


def test_build_parsed_configuration(raw_config_full):
    config = loads_configuration(raw_config_full)
    raw_built_config = dumps_configuration(config)
    assert raw_built_config == raw_config_full, "Built configuration is different then the original one"


def test_parse_config_columns_sanity(raw_config_full):
    config = loads_configuration(raw_config_full)
    assert len(config["Columns"]) == 64, "Unexpected columns length"
    assert all(0 <= width <= 0xffff for width in config["Columns"]), "Unexpected column width size"
    assert len(config["ColumnMap"]) == 64, "Unexpected column map length"
    columns_width = [width for width in config["Columns"] if width > 0]
    columns_map = [column for column in config["ColumnMap"] if column != Column.NONE]
    assert len(columns_width) == len(columns_map) == config["ColumnCount"], "Unexpected"


def test_parse_config_paths_sanity(raw_config_full):
    config = loads_configuration(raw_config_full)
    assert config["DbgHelpPath"] == "C:\\Windows\\SYSTEM32\\dbghelp.dll", "Unexpected DbgHelpPath"
    assert config["SymbolPath"] == "srv*https://msdl.microsoft.com/download/symbols", "Unexpected SymbolPath"


def test_parse_filter_rules_sanity(raw_config_full):
    config = loads_configuration(raw_config_full)
    assert 0 == len(config["HighlightRules"]), "HighlightRules should be an empty list"
    assert 25 == len(config["FilterRules"]), "Unexpected FilterRules length"
    assert config["FilterRules"][0] == Rule(Column.PROCESS_NAME, RuleRelation.IS, "python.exe", RuleAction.INCLUDE)
