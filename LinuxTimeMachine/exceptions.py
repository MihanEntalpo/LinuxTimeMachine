class Base(Exception):
    pass


class SrcNotFound(Base):
    pass


class SshError(Base):
    pass


class Timeout(Base):
    pass


class ConfigError(Base):
    pass


class ConfigFolderNotExists(ConfigError):
    pass


class BadConfigFile(Base):
    pass


class MysqlError(Base):
    pass


class RsyncError(Base):
    pass


class ConsoleError(Base):
    pass