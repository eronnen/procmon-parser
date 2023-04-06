"""
Python types that procmon configuration uses
"""

from six import string_types

from procmon_parser.consts import Column, RuleAction, RuleRelation

__all__ = ['Column', 'RuleAction', 'RuleRelation', 'Rule', 'Font']


class Rule(object):
    """A rule that can be used to filter procmon events.
    """

    def __init__(self, column=Column.ARCHITECTURE, relation=RuleRelation.IS, value="64-bit", action=RuleAction.INCLUDE):
        self.column = Column[column.upper()] if isinstance(column, string_types) else Column(column)
        self.relation = RuleRelation[relation.upper()] if isinstance(relation, string_types) else RuleRelation(relation)
        if not isinstance(value, string_types):
            raise TypeError("Filter value must be a string")
        self.value = value
        self.action = RuleAction[action.upper()] if isinstance(action, string_types) else RuleAction(action)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "If {} {} \"{}\", then {}".format(self.column.name.capitalize(), self.relation.name.lower(), self.value,
                                                 self.action.name.capitalize())

    def __repr__(self):
        return "Rule(Column.{}, Relation.{}, \"{}\", Action.{})".format(self.column.name, self.relation.name,
                                                                        self.value, self.action.name)

    def __hash__(self):
        return hash((self.column.value, self.relation.value, self.value, self.action.value))


class Font(object):
    """A font attributes for procmon, like in LOGFONTW structure
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
