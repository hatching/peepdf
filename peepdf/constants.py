#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Here is defined info about the project, its author
and some constants to customize

"""

import os
import sys

PEEPDF_VERSION = '0.3' 
PEEPDF_REVISION = '275'
AUTHOR = 'Jose Miguel Esparza'
AUTHOR_EMAIL = 'peepdf AT eternal-todo(dot)com'
AUTHOR_TWITTER = 'http://twitter.com/EternalTodo'
LICENCE = "GNU GPLv3"
PEEPDF_URL = 'http://peepdf.eternal-todo.com'
GITHUB_URL = 'https://github.com/jesparza/peepdf' 
TWITTER_URL = 'http://twitter.com/peepdf'

PEEPDF_ROOT = os.path.dirname(
    os.path.realpath(os.path.join(sys.argv[0], ".."))
)
ERROR_FILE = os.path.join(PEEPDF_ROOT, "errors.txt") 
