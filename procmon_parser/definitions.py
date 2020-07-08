"""
Definitions
"""
import enum

__all__ = ['RuleAction', 'RuleRelation', 'Column', 'Rule']


class RuleAction(enum.IntEnum):
    EXCLUDE = 0
    INCLUDE = 1


class RuleRelation(enum.IntEnum):
    IS = 0
    IS_NOT = 1
    LESS_THAN = 2
    MORE_THAN = 3
    BEGINS_WITH = 4
    ENDS_WITH = 5
    CONTAINS = 6
    EXCLUDES = 7


class Column(enum.IntEnum):
    NONE = 0
    DATE_AND_TIME = 40052
    PROCESS_NAME = 40053
    PID = 40054
    OPERATION = 40055
    RESULT = 40056
    DETAIL = 40057
    SEQUENCE = 40058
    COMPANY = 40064
    DESCRIPTION = 40065
    COMMAND_LINE = 40066
    USER = 40067
    IMAGE_PATH = 40068
    SESSION = 40069
    PATH = 40071
    TID = 40072
    RELATIVE_TIME = 40076
    DURATION = 40077
    TIME_OF_DAY = 40078
    VERSION = 40081
    EVENT_CLASS = 40082
    AUTHENTICATION_ID = 40083
    VIRTUALIZED = 40084
    INTEGRITY = 40085
    CATEGORY = 40086
    PARENT_PID = 40087
    ARCHITECTURE = 40088
    COMPLETION_TIME = 40164


class Rule(object):
    """
    A rule that can be used to filter procmon events.
    """

    def __init__(self, column=Column.ARCHITECTURE, relation=RuleRelation.IS, action=RuleAction.INCLUDE, value="64-bit"):
        self.column = column
        self.relation = relation
        self.action = action
        self.value = value

    def __str__(self):
        return "If {} {} \"{}\", then {}".format(self.column.name.capitalize(), self.relation.name.lower(), self.value,
                                                 self.action.name.capitalize())

    def __repr__(self):
        return "Rule(column={}, relation={}, action={}, value={})".format(str(self.column), str(self.relation),
                                                                          str(self.action), self.value)


class Font(object):
    """
    A font attributes for procmon, like in LOGFONTW structure
    see https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-logfontw for documentation
    """

    def __init__(self, height=8, width=0, escapement=0, orientation=0, weight=0, italic=0, underline=0, strikeout=0,
                 char_set=0, out_precision=0, clip_precision=0, quality=0, pitch_and_family=0,
                 face_name="MS Shell Dlg"):
        self.height = height
        self.width = width
        self.escapement = escapement
        self.orientation = orientation
        self.weight = weight
        self.italic = italic
        self.underline = underline
        self.strikeout = strikeout
        self.char_set = char_set
        self.out_precision = out_precision
        self.clip_precision = clip_precision
        self.quality = quality
        self.pitch_and_family = pitch_and_family
        self.face_name = face_name
