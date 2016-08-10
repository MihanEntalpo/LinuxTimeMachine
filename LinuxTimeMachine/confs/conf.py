#!/usr/bin/python3
"""
Здесь находися конфигурация скриптов резервного копирования
"""
root = "/home/backuper/backup"
paths = {
    "websites": root + "/websites",
    "machines": root + "/machines"
}
exclude_patterns = {
    "normal": ["*.log", "*~", "*.gvfs", ".cache*", ".dropbox*", "cache*", ".trash*"],
    "archives": ["*.tar", "*.gz", "*.rar", "*.zip"]
}



