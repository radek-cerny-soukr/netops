from dataclasses import dataclass, asdict, astuple, fields


@dataclass(frozen=True, slots=True)
class ConfigurationLimits:
    section_bytes: int = 64 * 1024 * 1024
    all_bytes: int = 256 * 1024 * 1024
    physical_line_bytes: int = 65536
    logical_record_bytes: int = 1024 * 1024
    idle_seconds: int = 30
    total_seconds: int = 600
    memory_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or not 1 <= value <= item.default:
                raise ValueError('invalid configuration limit: ' + item.name)
        if (self.section_bytes > self.all_bytes or
                self.physical_line_bytes > self.logical_record_bytes or
                self.logical_record_bytes > self.all_bytes or
                self.idle_seconds > self.total_seconds):
            raise ValueError('inconsistent configuration limits')

    @classmethod
    def from_mapping(cls, value):
        if type(value) is not dict or set(value) - {item.name for item in fields(cls)}:
            raise ValueError('invalid configuration limits')
        return cls(**value)

    def as_dict(self):
        return asdict(self)

    def identity(self):
        return astuple(self)
