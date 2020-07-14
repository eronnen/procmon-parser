# PMC File Format

PMC (Process Monitor Configuration file) is the file format which Procmon uses to store exported configurations in order to import them later from another instance of Procmon. There is no official documentation of this format so everything here was reverse engineered, and there are a few unknown fields.

The format is pretty simple - it's just an array of configuration options. Each configuration option is represented by 
a record structure, that contains the name of the option and its value. The record has the following layout:

**CONFIGURATION_RECORD**

| Data Type | Description                                                  |
| --------- | ------------------------------------------------------------ |
| Uint32    | The size of the record                                       |
| Uint32    | The size of the first 4 fields (0x10)                        |
| Uint32    | The size of the first 5 fields (0x10 plus name size in bytes) |
| Uint32    | The size of the data                                         |
| Wchar_t[] | The name of the configuration option                         |
| Byte[]    | the value of the configuration option (format depends on which option it is) |

In the default configuration of Procmon, there are 20 configuration options:

* `Columns` (Uint32) - array of the width of the GUI columns in pixels, from left column to right.
* `ColumnCount` (Uint32) - the number of columns to show in the GUI.
* `ColumnMap` (Uint32[]) - ordered array of the column types to show.
* `DbgHelpPath` (wchar_t[]) - path to *dbghelp.dll* to use for the stack traces.
* `Logfile` - an optional path to a PML file to store the captured events.
* `HighlightFG` (Uint32) - the foreground color to use for highlighted events.
* `HighlightBG` (Uint32) - the background color to use for highlighted events.
* `LogFont` (LOGFONTW) - the font to use for display. see https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-logfontw
* `BoookmarkFont` (LOGFONTW)  they have that typo... see https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-logfontw
* `AdvancedMode` - if enabled causes Procmon to view the operation names as IRP names.
* `Autoscroll` (Uint32) - whether to scroll automatically for new events.
* `HistoryDepth` (Uint32)- limits the number of events that Procmon writes to the log file - in millions.
* `Profiling` (Uint32) - whether to generate thread profiling event every 1 second.
* `DestructiveFilter` (Uint32) - whether to not write events that the current filters exclude to the log file.   
* `AlwaysOnTop` (Uint32) - whether to make the GUI window remain on top of other windows.
* `ResolveAddresses` (Uint32) -  
* `SourcePath` (Wchar_t[]) - path to look for sources of the symbols.
* `SymbolPath` (Wchar_t[]) - symbol server path.
* `FilterRules` (FILTER_RULES) - a list of rules to filter events in or out.
* `HighlightRules` (FILTER_RULES) - a list of rules for highlighting specific events.

The filter rules are represented by the following layout:

**FILTER_RULES**

| Data Type     | Description                      |
| ------------- | -------------------------------- |
| Byte          | Unknown                          |
| Byte          | the number of rules in the array |
| FILTER_RULE[] | array of all the rules           |
| Byte[3]       | Unknown                          |

Each filter rule contains the column type it checks  (like "PID", "Path", ...), the relation type (like "is", "contains", "starts with", ...) and the value to compare to, and whether to include events that matches this rule or exclude them. A rule is represented by the following layout:

**FILTER_RULE**

| Data Type | Description                                                  |
| --------- | ------------------------------------------------------------ |
| Byte[3]   | Unknown                                                      |
| Uint32    | Column type - see ```class Column(enum.IntEnum)``` in [consts.py](../procmon_parser/consts.py) |
| Uint32    | Relation type  - see ```class RuleRelation(enum.IntEnum)``` in [consts.py](../procmon_parser/consts.py) |
| Byte      | Whether to include this filter if it matches an event or exclude it. |
| Uint32    | The length of the value string in bytes                      |
| Wchar_t[] | The value                                                    |
| Byte[5]   | Unknown                                                      |

