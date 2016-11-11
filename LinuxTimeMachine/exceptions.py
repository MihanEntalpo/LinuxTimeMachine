class Base(Exception):
    pass


class SrcNotFound(Base):
    def __init__(self, path, host):
        self.path = path
        self.host = host


class SshError(Base):
    pass


class Timeout(Base):
    pass


class ConfigError(Base):
    pass

class ConfigFileNotExists(ConfigError):
    pass

class ConfigFolderNotExists(ConfigError):
    pass


class BadConfigFile(ConfigError):
    pass


class MysqlError(Base):
    pass


class RsyncError(Base):
    pass


class ConsoleError(Base):
    pass

class RemoveFileNotSuccessfull(ConsoleError):
    def __init__(self, filename, sshhost):
        self.filename = filename
        self.sshhost = sshhost