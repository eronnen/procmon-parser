#pragma endian little
#pragma author "eronnen"
#pragma description "Sysinternals Process Monitor Configuration (PMC) File Pattern"
#pragma file_format "pmc"
#pragma MIME "application/x-procmon-configuration"
#pragma array_limit 2000000
#pragma pattern_limit 20971520

#include <std/sys.pat>
#include <std/mem.pat>
#include <std/io.pat>
#include <std/string.pat>

/* =========================================================================
 * Formatter Functions & Helper Types
 * ========================================================================= */

fn clean_string(str s) {
    u32 len = std::string::length(s);
    while (len > 0) {
        if (std::string::at(s, len - 1) == '\0' || std::string::at(s, len - 1) == char(0)) {
            len = len - 1;
        } else {
            break;
        }
    }
    return std::string::substr(s, 0, len);
};

fn format_colorref(u32 color) {
    u8 r = u8(color & 0xFF);
    u8 g = u8((color >> 8) & 0xFF);
    u8 b = u8((color >> 16) & 0xFF);
    return std::format("RGB({}, {}, {}) [0x{:06X}]", r, g, b, color & 0x00FFFFFF);
};

/* =========================================================================
 * Enums
 * ========================================================================= */

enum RuleAction : u8 {
    Exclude = 0,
    Include = 1
};

enum RuleRelation : u32 {
    Is         = 0,
    IsNot      = 1,
    LessThan   = 2,
    MoreThan   = 3,
    BeginsWith = 4,
    EndsWith   = 5,
    Contains   = 6,
    Excludes   = 7
};

enum Column : u32 {
    None             = 0,
    DateAndTime      = 40052,
    ProcessName      = 40053,
    PID              = 40054,
    Operation        = 40055,
    Result           = 40056,
    Detail           = 40057,
    Sequence         = 40058,
    Company          = 40064,
    Description      = 40065,
    CommandLine      = 40066,
    User             = 40067,
    ImagePath        = 40068,
    Session          = 40069,
    Path             = 40071,
    TID              = 40072,
    RelativeTime     = 40076,
    Duration         = 40077,
    TimeOfDay        = 40078,
    Version          = 40081,
    EventClass       = 40082,
    AuthenticationID = 40083,
    Virtualized      = 40084,
    Integrity        = 40085,
    Category         = 40086,
    ParentPID        = 40087,
    Architecture     = 40088,
    CompletionTime   = 40164,
    ProcessStart     = 40178
};

enum FontWeight : s32 {
    FW_DONTCARE   = 0,
    FW_THIN       = 100,
    FW_EXTRALIGHT = 200,
    FW_LIGHT      = 300,
    FW_NORMAL     = 400,
    FW_MEDIUM     = 500,
    FW_SEMIBOLD   = 600,
    FW_BOLD       = 700,
    FW_EXTRABOLD  = 800,
    FW_HEAVY      = 900
};

enum FontQuality : u8 {
    DEFAULT_QUALITY        = 0,
    DRAFT_QUALITY          = 1,
    PROOF_QUALITY          = 2,
    NONANTIALIASED_QUALITY = 3,
    ANTIALIASED_QUALITY    = 4,
    CLEARTYPE_QUALITY      = 5
};

enum FontCharSet : u8 {
    ANSI_CHARSET        = 0,
    DEFAULT_CHARSET     = 1,
    SYMBOL_CHARSET      = 2,
    MAC_CHARSET         = 77,
    SHIFTJIS_CHARSET    = 128,
    HANGUL_CHARSET      = 129,
    JOHAB_CHARSET       = 130,
    GB2312_CHARSET      = 134,
    CHINESEBIG5_CHARSET = 136,
    GREEK_CHARSET       = 161,
    TURKISH_CHARSET     = 162,
    VIETNAMESE_CHARSET  = 163,
    HEBREW_CHARSET      = 177,
    ARABIC_CHARSET      = 178,
    BALTIC_CHARSET      = 186,
    RUSSIAN_CHARSET     = 204,
    THAI_CHARSET        = 222,
    EASTEUROPE_CHARSET  = 238,
    OEM_CHARSET         = 255
};

fn format_column_name(Column col) {
    match (col) {
        (Column::None):             return "None";
        (Column::DateAndTime):      return "Date & Time";
        (Column::ProcessName):      return "Process Name";
        (Column::PID):              return "PID";
        (Column::Operation):        return "Operation";
        (Column::Result):           return "Result";
        (Column::Detail):           return "Detail";
        (Column::Sequence):         return "Sequence";
        (Column::Company):          return "Company";
        (Column::Description):      return "Description";
        (Column::CommandLine):      return "Command Line";
        (Column::User):             return "User";
        (Column::ImagePath):        return "Image Path";
        (Column::Session):          return "Session";
        (Column::Path):             return "Path";
        (Column::TID):              return "TID";
        (Column::RelativeTime):     return "Relative Time";
        (Column::Duration):         return "Duration";
        (Column::TimeOfDay):        return "Time of Day";
        (Column::Version):          return "Version";
        (Column::EventClass):       return "Event Class";
        (Column::AuthenticationID): return "Authentication ID";
        (Column::Virtualized):      return "Virtualized";
        (Column::Integrity):        return "Integrity";
        (Column::Category):         return "Category";
        (Column::ParentPID):        return "Parent PID";
        (Column::Architecture):     return "Architecture";
        (Column::CompletionTime):   return "Completion Time";
        (Column::ProcessStart):     return "Process Start";
        (_):                        return std::format("0x{:04X}", u32(col));
    }
};

fn format_rule_rel(RuleRelation rel) {
    match (rel) {
        (RuleRelation::Is):         return "is";
        (RuleRelation::IsNot):      return "is not";
        (RuleRelation::LessThan):   return "less than";
        (RuleRelation::MoreThan):   return "more than";
        (RuleRelation::BeginsWith): return "begins with";
        (RuleRelation::EndsWith):   return "ends with";
        (RuleRelation::Contains):   return "contains";
        (RuleRelation::Excludes):   return "excludes";
        (_):                        return "matches";
    }
};

/* =========================================================================
 * Configuration Option Structures
 * ========================================================================= */

struct LOGFONTW {
    s32 lfHeight [[comment("Font height in logical units")]];
    s32 lfWidth [[comment("Average character width in logical units")]];
    s32 lfEscapement [[comment("Angle of escapement in tenths of degrees")]];
    s32 lfOrientation [[comment("Angle of orientation in tenths of degrees")]];
    FontWeight lfWeight [[comment("Font weight: 400=Normal, 700=Bold")]];
    u8 lfItalic [[comment("Italic flag (0 or 1)")]];
    u8 lfUnderline [[comment("Underline flag (0 or 1)")]];
    u8 lfStrikeOut [[comment("Strikeout flag (0 or 1)")]];
    FontCharSet lfCharSet [[comment("Character set")]];
    u8 lfOutPrecision [[comment("Output precision")]];
    u8 lfClipPrecision [[comment("Clipping precision")]];
    FontQuality lfQuality [[comment("Output quality")]];
    u8 lfPitchAndFamily [[comment("Pitch and family")]];
    char16 lfFaceName[32] [[comment("Typeface name (up to 32 characters including null terminator)")]];
};

fn format_logfont(LOGFONTW font) {
    str name = clean_string(std::string::to_string(font.lfFaceName));
    str weight_str = "Normal";
    if (font.lfWeight >= 700) {
        weight_str = "Bold";
    }
    return std::format("Font: \"{}\" (size: {}, {})", name, font.lfHeight, weight_str);
};

struct FilterRule {
    Column column [[comment("Column type to filter on")]];
    RuleRelation relation [[comment("Comparison relation (is, begins with, contains, etc.)")]];
    RuleAction action [[comment("Filter action (Exclude=0, Include=1)")]];
    u32 value_length [[comment("Length of value string in bytes (including null terminator)")]];
    if (value_length > 0) {
        char16 value[value_length / 2] [[comment("Comparison value string (UTF-16LE)")]];
    }
    u32 int_value [[comment("Integer comparison value (e.g. PID or architecture 32/64)")]];
    u32 reserved [[comment("Reserved / unknown field (always 0)")]];
};

fn format_filter_rule(FilterRule rule) {
    str act = (rule.action == RuleAction::Include) ? "Include" : "Exclude";
    str col = format_column_name(rule.column);
    str rel = format_rule_rel(rule.relation);
    str val = "";
    if (rule.value_length > 0) {
        val = clean_string(std::string::to_string(rule.value));
    } else {
        val = std::format("{}", rule.int_value);
    }
    return std::format("{} if {} {} \"{}\"", act, col, rel, val);
};

struct FilterRulesData {
    u8 reserved [[comment("Reserved byte (always 1)")]];
    u32 rules_count [[comment("Number of filter rules in array")]];
    FilterRule rules[rules_count] [[comment("Filter rules array")]];
};

fn format_filter_rules_summary(FilterRulesData data) {
    return std::format("{} rule(s)", data.rules_count);
};

/* =========================================================================
 * Configuration Record Structure
 * ========================================================================= */

struct ConfigurationRecord {
    u32 record_size [[comment("Total size of the record in bytes"), color("4A90E2")]];
    u32 header_size [[comment("Header size (always 0x10 = 16 bytes)"), color("4A90E2")]];
    u32 header_and_name_size [[comment("Header size + Name string length in bytes"), color("4A90E2")]];
    u32 data_size [[comment("Data payload size in bytes"), color("4A90E2")]];

    char16 name[(header_and_name_size - 16) / 2] [[comment("Option name (UTF-16LE null-terminated)"), color("FFD700")]];

    if (std::string::starts_with(std::string::to_string(name), "ColumnCount")) {
        u32 column_count [[comment("Number of columns shown in GUI")]];
    } else if (std::string::starts_with(std::string::to_string(name), "ColumnMap")) {
        Column column_map[data_size / 4] [[comment("Ordered array of column types to show")]];
    } else if (std::string::starts_with(std::string::to_string(name), "Columns")) {
        u16 column_widths[data_size / 2] [[comment("Column widths in pixels")]];
    } else if (std::string::starts_with(std::string::to_string(name), "DbgHelpPath")) {
        if (data_size > 0) {
            char16 dbghelp_path[data_size / 2] [[comment("Path to dbghelp.dll for stack traces")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "Logfile")) {
        if (data_size > 0) {
            char16 logfile_path[data_size / 2] [[comment("Path to PML log file to capture events")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "HighlightFG")) {
        if (data_size == 4) {
            u32 highlight_fg [[comment("Foreground color (COLORREF: 0x00BBGGRR)"), format("format_colorref")]];
        } else if (data_size > 0) {
            u8 highlight_fg_data[data_size] [[comment("Foreground color data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "HighlightBG")) {
        if (data_size == 4) {
            u32 highlight_bg [[comment("Background color (COLORREF: 0x00BBGGRR)"), format("format_colorref")]];
        } else if (data_size > 0) {
            u8 highlight_bg_data[data_size] [[comment("Background color data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "LogFont")) {
        if (data_size == sizeof(LOGFONTW)) {
            LOGFONTW log_font [[comment("Main display font (LOGFONTW)"), format("format_logfont")]];
        } else if (data_size > 0) {
            u8 log_font_data[data_size] [[comment("LogFont data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "BoookmarkFont")) {
        if (data_size == sizeof(LOGFONTW)) {
            LOGFONTW bookmark_font [[comment("Bookmark font (LOGFONTW)"), format("format_logfont")]];
        } else if (data_size > 0) {
            u8 bookmark_font_data[data_size] [[comment("Bookmark font data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "AdvancedMode")) {
        u32 advanced_mode [[comment("If enabled, shows operation names as IRP names (0=Disabled, 1=Enabled)")]];
    } else if (std::string::starts_with(std::string::to_string(name), "Autoscroll")) {
        u32 autoscroll [[comment("Autoscroll on new events (0=Disabled, 1=Enabled)")]];
    } else if (std::string::starts_with(std::string::to_string(name), "HistoryDepth")) {
        u32 history_depth [[comment("History depth limit in millions of events")]];
    } else if (std::string::starts_with(std::string::to_string(name), "Profiling")) {
        u32 profiling [[comment("Thread profiling every 1 second (0=Disabled, 1=Enabled)")]];
    } else if (std::string::starts_with(std::string::to_string(name), "DestructiveFilter")) {
        u32 destructive_filter [[comment("Discard events excluded by filters (0=Disabled, 1=Enabled)")]];
    } else if (std::string::starts_with(std::string::to_string(name), "AlwaysOnTop")) {
        u32 always_on_top [[comment("Window always on top (0=Disabled, 1=Enabled)")]];
    } else if (std::string::starts_with(std::string::to_string(name), "ResolveAddresses")) {
        u32 resolve_addresses [[comment("Resolve addresses to symbols (0=Disabled, 1=Enabled)")]];
    } else if (std::string::starts_with(std::string::to_string(name), "SourcePath")) {
        if (data_size > 0) {
            char16 source_path[data_size / 2] [[comment("Source code search path")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "SymbolPath")) {
        if (data_size > 0) {
            char16 symbol_path[data_size / 2] [[comment("Symbol server / PDB path")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "FilterRules")) {
        FilterRulesData filter_rules [[comment("Filter rules applied to events"), format("format_filter_rules_summary")]];
    } else if (std::string::starts_with(std::string::to_string(name), "HighlightRules")) {
        FilterRulesData highlight_rules [[comment("Highlight rules applied to events"), format("format_filter_rules_summary")]];
    } else if (std::string::starts_with(std::string::to_string(name), "Theme")) {
        if (data_size > 0) {
            u8 theme_data[data_size] [[comment("Theme data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "FlightRecorder")) {
        if (data_size == 4) {
            u32 flight_recorder [[comment("Flight recorder setting")]];
        } else if (data_size > 0) {
            u8 flight_recorder_data[data_size] [[comment("Flight recorder data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "RingBufferSize")) {
        if (data_size == 4) {
            u32 ring_buffer_size [[comment("Ring buffer size in MB")]];
        } else if (data_size > 0) {
            u8 ring_buffer_size_data[data_size] [[comment("Ring buffer size data")]];
        }
    } else if (std::string::starts_with(std::string::to_string(name), "RingBufferMin")) {
        if (data_size == 4) {
            u32 ring_buffer_min [[comment("Ring buffer minimum")]];
        } else if (data_size > 0) {
            u8 ring_buffer_min_data[data_size] [[comment("Ring buffer min data")]];
        }
    } else {
        if (data_size > 0) {
            u8 data[data_size] [[comment("Custom or unrecognized option payload"), color("A0A0A0")]];
        }
    }

    // Ensure cursor advances to the end of the record regardless of payload structure
    u128 expected_end = addressof(this) + record_size;
    if ($ < expected_end) {
        u8 padding[expected_end - $] [[comment("Remaining unparsed bytes / padding"), color("808080")]];
    }
} [[name(clean_string(std::string::to_string(name)))]];

/* =========================================================================
 * Top-level File Layout
 * ========================================================================= */

ConfigurationRecord records[while(!std::mem::eof())] @ 0x00;
