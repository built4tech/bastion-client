import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import os

#LOGFOLDER = "/usr/local/share/bastion-app/logs"
#logFile= LOGFOLDER + os.sep + 'observer.log'

LOGFOLDER = os.curdir + os.sep + 'log'
logFile= LOGFOLDER + os.sep + 'observer.log'


def log_setup():
	''' Setting up the logger '''

	logger = logging.getLogger('myapp')

	if not os.path.exists(LOGFOLDER):
	    os.makedirs(LOGFOLDER)

	'''
	    Rotating log file with size of 5Mb.
	'''
	hdlr = RotatingFileHandler(logFile, mode='a', maxBytes=(4*1000*1000), backupCount=10, encoding=None, delay=0)

	'''
	    Value        Type of interval
	    's'            Seconds
	    'm'            Minutes
	    'h'            Hours
	    'd'            Days
	    'w0'-'w6'    Weekday (0=Monday)
	    'midnight'    Roll over at midnight

	    will rotate logs 3 days once

	hdlr = TimedRotatingFileHandler(logFile, when="d", interval=3, backupCount=100, encoding=None, delay=0) 
	'''
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	logger.addHandler(hdlr)

	# CMG - Screen also in screen
	console_hdlr = logging.StreamHandler()
	console_hdlr.setFormatter(formatter)
	logger.addHandler(console_hdlr)
	# ***********************

	logger.setLevel(logging.INFO)
	return logger


logger = log_setup()
logger.info('LOGGER - Logger initialized')