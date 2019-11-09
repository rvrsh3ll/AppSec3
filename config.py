import os

class DefaultConfig(object):
	DEBUG = True
	SECRET_KEY = os.urandom(64)