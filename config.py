import os

class DefaultConfig(object):
	DEBUG = False
	SECRET_KEY = os.urandom(64)