#!/usr/bin/env python

__VERSION__ =  "0.0.1"

#---------------------------

import argparse
from datetime import datetime
from functools import *
import hashlib
import inspect
import logging
import os
import paramiko.client
from paramiko.ssh_exception import AuthenticationException, SSHException, BadHostKeyException, BadAuthenticationType
import Queue
import re
import stat
import subprocess
import socket
import sys
import threading
import multiprocessing
import time
import json

#--------------------------------------
# Globals

LOG_LEVEL = 'INFO'  # supported levels: 'DEBUG', 'INFO'

_SEQUENTIAL_     = 1
_MULTITHREADED_  = 2
_MULTIPROCESSOR_ = 3
_RUN_TYPE_ = _MULTIPROCESSOR_
num_update_threads = 20

#--------------------------------------
# communication classes

class Ssh(object):
    client = None

    def __init__(self, logger, host, user, password, port='22'):
        '''
        Initialize defaults
        '''
        self.client = None

        # init params:
        self.host = host
        self.user = user
        self.password = password
        self.port = int(port)
        self.child = None
        self.logger = logger

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.connect()

        except Exception as e:
            msg = "[" + self.host + "] SSH error: " + str(e)
            self.logger.error(msg)
            raise Exception(msg)

    def connect(self):
        try:
            self.client.connect(self.host, self.port, self.user, self.password)
            self.sftp = self.client.open_sftp()

        except AuthenticationException:
            raise Exception("[" + self.host + "] Authentication failed, verify credentials")
        except BadAuthenticationType:
            raise Exception("[" + self.host + "] Bad Authentication type, verify credentials")
        except BadHostKeyException as e:
            raise Exception("[" + self.host + "] Unable to verify server's host key: " + str(e))
        except SSHException as e:
            raise Exception("[" + self.host + "] Unable to establish SSH connection: " + str(e))
        except socket.error as e:
            raise Exception("[" + self.host + "] Socket error connecting: " + str(e))
        except EOFError as e:
            raise Exception("[" + self.host + "] Server has terminated with EOFError: " + str(e))
        except Exception as e:
            raise Exception("[" + self.host + "] SSH error" + str(e))

        channel = self.client.invoke_shell()
        self.stdin = channel.makefile('wb')
        self.stdout = channel.makefile('r')

    def close(self):
        if self.ssh.sftp is not None:
            self.ssh.sftp.close()
        self.ssh.sftp = None
        if self.client:
            self.client.close()

    def cmd(self, command):
        if self.client:
            stdin, stdout, stderr = self.client.exec_command(command)
            rc = stdout.channel.recv_exit_status()
            return rc, stdout.readlines(), stderr.readlines()
        else:
            raise Exception("[" + self.host + "] Connection not open")

    def join_file(self, filename):
        # cat installer.part* > installer.zip
        try:
            shIn, shOut, shErr = self.ssh.cmd("cat " + filename + ".part* > " + filename + ".zip")
            if shErr:
                raise Exceptioin(shErr)
        except Exception as err:
            self.logger.error("[" + self.remote_ip + "] join " + filename + " failed")
            return False
        return True


class LocalCmd():
    def __init__(self, logger):
        self.logger = logger

    def cmd(self, line):
        stdout = stderr = ""
        rc = -1

        self.logger.debug('shell snd: %s', line)

        try:
            p = subprocess.Popen(line.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            rc = p.returncode
        except Exception as err:
            raise Exception("subprocess failed with: %s" % str(err))

        buffer = stdout + stderr
        self.logger.debug('shell rcv: %s', str(buffer.strip()))

        return rc, stdout, stderr


    def checksum(self, file):
        try:
            filehash = hashlib.md5()
            filehash.update(open(file).read())
            return filehash.hexdigest()
        except:
            return ""

    def ping(self, address, n = 10):
        count_flag = '-c'
        try:
            ping = subprocess.Popen(['ping', address, count_flag, str(n)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = ping.communicate()
            try:
                summary = re.findall(r'rtt min/avg/max/mdev = (\S+)', stdout)[0]
                minimum, average, maximum, mdev = \
                    (float(x) for x in summary.split('/'))

                lost = int(re.findall(r'(\d+)% packet loss', stdout)[0])
            except:
                return(None, None, None, None)

        except subprocess.CalledProcessError:
            return(None, None, None, None)
        
        self.logger.info('Ping rtt (min/avg/max/mdev) : %d %d %d %d ', minimum, maximum, average, lost)
        return (minimum, maximum, average, lost)

    def split_file(path, filename, targetdir='part', blkcount='50'):
        # split -n 50 -e -d installer.zip "installer.part"
        try:
            # check if checksum tool exists
            cmd = 'split -n '+ blkcount +' -e -d '+ path + '/' + filename +' '+ path + '/' + targetdir + '/' + filename +'.part"'
            rc, buffer = self.cmd(cmd)
            if rc != 0:
                raise Exception('Split failed')

            splitFiles = {}

            # get split names from buffer
            listing = os.listdir(path + '/'+ targetdir)
            for file in listing:
                if file.startswith(filename + '.part'):
                    # get file checksum
                    chksum = self.checksum( path + '/'+ targetdir + '/' + file)
                    splitFiles[file] = chksum

            if len(splitFiles) != blkcount:
                raise Exception('Split failed')

            return splitFiles

        except Exception as err:
            raise Exception('Split failed : ' + str(err))


#--------------------------------------
# logging

def init_logger(log_file, level, log_to_stdout=False):

    # define logging levels
    levels = {'INFO' : logging.INFO,
              'DEBUG' : logging.DEBUG}

    # initialize logger:
    try:
        logger = logging.getLogger()

        try:
            logger.setLevel(levels[level])
        except Exception:
            logger.setLevel(logging.INFO)

        formatter = logging.Formatter('[%(asctime)s][%(processName)-10s][%(threadName)-9s][%(lineno)-4d][%(levelname)-4s]  %(message)s')

        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        if log_to_stdout:
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            logger.addHandler(console)

    except Exception as err:
        msg = "ERROR: Unable to initialize logger object: %s" % str(err)
        raise Exception(msg)

    logger.info('All messages are being logged to %s' % log_file)

    return logger


#--------------------------------------
# Threading and Processes

class wThead(threading.Thread):

    def __init__(self, logger, function, module, queue, options):
        threading.Thread.__init__(self)
        self.logger = logger
        self.function = function
        self.module = module
        self.options = options
        self.queue = queue

        self.daemon = True

        self.emptyCheck = 0
        self._return = None

    def run(self):
        while True:
            try:
                msg = self.queue.get(True, 5)
                data = json.loads(msg)
                self.function( data['device'], self.module, self.logger, self.options )
            except Queue.Empty:
                break
            except Exception as err:
                pass

    def join(self):
        threading.Thread.join(self)
        return self._return

class wProcess(multiprocessing.Process):

    def __getstate__(self):
        # Process safe copy
        d = self.__dict__.copy()
        if 'function' in d:
            d['function'] = d['function'].name
        if 'module' in d:
            d['module'] = d['module'].name
        if 'logger' in d:
            d['logger'] = d['logger'].name
        if 'queue' in d:
            d['queue'] = d['queue'].name
        if 'options' in d:
            d['options'] = d['options'].name
        return d

    def __setstate__(self):
        # Process safe copy
        if 'logger' in d:
            d['logger'] = logging.getLogger(d['logger'])
        self.__dict__.update(d)

    def __init__(self, logger, function, module, queue, options):
        multiprocessing.Process.__init__(self)
        self.logger = logger
        self.function = function
        self.module = module
        self.options = options
        self.queue = queue
        self.threads = []

        self.daemon = True

    def run(self):
        try:
            # Set up some threads to fetch the enclosures
            for i in range(num_update_threads):
                t = wThead(self.logger, self.function, self.module, self.queue, self.options)
                t.daemon = True
                self.threads.append(t)
                t.start()

            for t in self.threads:
                t.join()

            while self.threads:
                for t in self.threads:
                    if not t.isAlive():
                        self.threads.remove(t)

        except(KeyboardInterrupt, SystemExit):
            self.stop()

        except Exception as err:
            self.stop()

#--------------------------------------
# usage

def usage():
    return '''
        device_manager.py -m <module> (module options) -u <username> -p <password> -r <remote_port> -d <device(s)>

        python device_manager.py -m <module> (module options) -u user -p pswd1234 -r 22 -d 10.0.0.1
        python device_manager.py -m <module> (module options) -u user -p pswd1234 -r 22 -d 10.0.0.1,10.0.0.2,10.0.0.3
        python device_manager.py -m <module> (module options) -u user -p pswd1234 -r 22 -d devicelist.txt

        -m -m <module> is the module to be run across the devices

        -d will identify if the command line contains either
            1) single device id
                -d 10.0.0.1
            2) multiple IDs comma delimited WITHOUT SPACES
                -d 10.0.0.1,10.0.0.2,10.0.0.3
            3) filename of file with a list of device IDs
                -d devicelist.txt

        example devicelist.txt
            # Hash comments allowed
            10.0.0.1     # Device 1
            10.0.0.2     # hash comments allowed here too
            10.0.0.3     # Device 3
            ...
        '''

#--------------------------------------
# device module - inherited by work module

class InitModule(object):

    def __init__(self):
        super(InitModule,self).__init__()
        
        self.options = None
        self.name = "Not defined"
        self.description = "Not Defined"
        
    def using(self):
        pass

    def pre_run(self, shell, logger, options):
        pass

class DeviceModule(object):

    def __init__(self, logger, device, options):
        self.logger = logger
        self.device_ip = device[0]
        self.options = options
        
    def debug(self, msg):
        self.logger.debug("["+ self.device_ip + "] " + msg)

    def warn(self, msg):
        self.logger.warn("[" + self.device_ip + "] " + msg)

    def info(self, msg):
        self.logger.info("[" + self.device_ip + "] " + msg)

    def error(self, msg):
        self.logger.error("[" + self.device_ip + "] " + msg)

#--------------------------------------
# device client

class clientDevice():
    def __init__(self, logger, device, options):

        self.device_ip = device[0]

        self.remote_port = options.remoteport
        self.user = options.username
        self.password = options.password

        self.logger = logger

        self.transfer_p = 0
        self.transfer_start_time = 0

    def connect(self):
        try:
            # init ssh session to remote:
            self.ssh = Ssh(self.logger, self.device_ip, self.user, self.password, self.remote_port)
            return True

        except Exception as err:
            self.ssh = None
            self.logger.error("[" + self.device_ip + "] SSH Initialization error : " + str(err))
            return False

    def close(self):
        if self.ssh is not None:
            self.ssh.close()
        self.ssh = None

    def dir(self, path):
        shIn, shOut, shErr = self.ssh.cmd('ls')
        if shErr:
            raise Exception('unable to list folder')
        return buffer

    def progress_callback(self, x, y):
        try:
            if y > 0:
                percent = int(float(x*100)/(y))
                if not percent%10:
                    if percent > self.transfer_p:
                        self.transfer_p = percent
                        elapsed_time = time.time() - self.transfer_start_time
                        kbps = int(float((x/1024) / elapsed_time))
                        self.logger.info( "[" + self.device_ip + "] " + str( (x,y) ) + "  " + str(percent) + "% " + str(kbps) + " Kb/s")
        except Exception as err:
            self.logger.info('Problem with transfer reporting : ' + str(err))
            pass

    def copyToDevice(self, localFile, devFile):
        self.transfer_p = 0
        self.transfer_start_time = time.time()
        self.ssh.sftp.put(localFile, devFile, self.progress_callback)

    def copyFromDevice(self, devFile, localFile):
        self.transfer_p = 0
        self.transfer_start_time = time.time()
        self.ssh.sftp.get(devFile, localFile, self.progress_callback)

    def chdir(self, path):
        try:
            self.ssh.sftp.chdir(path)
            return True
        except IOError:
            logger.error("[" + device_ip + "] Required path does not exist")
            return False
        except Exception as err:
            logger.error("[" + device_ip + "] Exception : " + str(err))
            return False

    def chmod(self, path, mode=755):
        self.ssh.sftp.chmod(path, mode)

    def copy(self, fromPath, toPath):
        cmd = 'cp ' + fromPath + ' ' + toPath
        shIn, shOut, shErr = self.ssh.cmd(cmd)
        if len(shErr) != 0:
            self.logger.error("[" + self.device_ip + "] error copying file : ")
            for e in shErr:
                self.logger.error("                      str(e)")
            return False
        return True

    def chown(self, path, uid, gid):
        self.ssh.sftp.chown(path, uid, gid)

    def dir(self, path):
        return self.listdir(path)

    def checksum(self, file):
        cmd = 'md5sum ' + file
        shIn, shOut, shErr = self.ssh.cmd(cmd)
        if len(shErr) != 0:
            self.logger.error("[" + self.device_ip + "] error getting checksum : ")
            for e in shErr:
                self.logger.error("                      str(e)")
            return None
        if shOut:
            if len(shOut[0]):
                return str(shOut[0]).split(' ', 1)[0]
        return None

    def getcwd(self):
        return self.ssh.sftp.getcwd()

    def listdir(self, path='.'):
        return self.ssh.sftp.listdir(path)

    def listdirectories(self, path='.'):
        listdir = []
        dir_items = self.ssh.sftp.listdir_attr(path)
        for item in dir_items:
            if stat.S_ISDIR(item.st_mode):
                listdir.append(item.filename)
        return listdir

    def listfiles(self, path='.'):
        listdir = []
        dir_items = self.ssh.sftp.listdir_attr(path)
        for item in dir_items:
            if stat.S_ISREG(item.st_mode):
                listdir.append(item.filename)
        return listdir

    def mkdir(self, path):
        try:
            self.ssh.sftp.mkdir(path)
            return True
        except IOError:
            # path already exists
            return True
        except Exception as err:
            logger.error("[" + device_ip + "] Exception : " + str(err))
            return False

        return self.listdir(path)

    def move(self, fromPath, toPath):
        # move with force flag
        cmd = 'mv --force ' + fromPath + ' ' + toPath
        shIn, shOut, shErr = self.ssh.cmd(cmd)
        if len(shErr) != 0:
            self.logger.error("[" + self.device_ip + "] error copying file : " )
            for e in shErr:
                self.logger.error("                      str(e)")
            return False
        return True

    def ping(self, limit=20, cnt=5):
        minimum, maximum, average, lost = ping(self.device_ip, cnt)
        msg = "[" + self.device_ip + "] PING : min/max/ave/lost : " + \
                str(minimum) + ', ' + str(maximum) + ', ' + str(average) + \
                ', ' + str(lost)
        self.logger.info(msg)

        if average > limit:
            msg = "[" + self.device_ip + "] PING is greater than " + \
                    str(limit) + " seconds - aborting device";
            self.logger.error(msg)
            return False
        return True

    def remove(self, file):
        try:
            self.ssh.sftp.remove(file)
            return True
        except IOError:
            logger.error("[" + device_ip + "] Unabble to remove file")
            return False
        except Exception as err:
            logger.error("[" + device_ip + "] Exception : " + str(err))
            return False

    def rename(self, old, new):
        self.ssh.sftp.rename(old, new)

    def rmdir(self, path):
        try:
            self.ssh.sftp.rmdir(path)
            return True
        except IOError:
            logger.error("[" + device_ip + "] Unabble to remove directory")
            return False
        except Exception as err:
            logger.error("[" + device_ip + "] Exception : " + str(err))
            return False

    def rmforce(self, path):
        cmd = 'rm -rf ' + path
        shIn, shOut, shErr = self.ssh.cmd(cmd)
        if len(shErr) != 0:
            self.logger.error("[" + self.device_ip + "] error copying file : " )
            for e in shErr:
                self.logger.error("                      str(e)")
            return False
        return True

    def cmd(self, cmd):
        shIn, shOut, shErr = self.ssh.cmd(cmd)
        if len(shErr) != 0:
            raise Exception('cmd error')
        return shOut

    def write(self, filename, contents):
        fp = self.ssh.sftp.file(filename, 'a', -1)
        fp.write(contents)
        fp.flush()


def progress_bar(title, curr, total, full_progbar):
    try:
        frac = curr/total
        filled_progbar = round(frac*full_progbar)
        text = "\r {0} : [{1}] {2}%".format(title, "#"*int(filled_progbar) + \
            "-"*int((full_progbar-filled_progbar)), frac*100)
        print text
    except:
        print "\r Runing..." + str(curr) + " of " + str(total)
        pass

#--------------------------------------
# rsa key cleanup

def remove_rsa_key(shell, device_ip, remote_port=22):
    '''
    Remove the rsa key for the given remote address. The purpose of this
    is to avoid ssh conflicts after rebooting the remote device.
    '''
    ip = device_ip
    port = str(remote_port)

    try:
        if str(port) == '22':
            shell.cmd("ssh-keygen -R %s" % ip)
        else:
            shell.cmd("ssh-keygen -R [%s]:%s" % (ip, port))
        return
    except Exception:
        pass

#--------------------------------------
# python file paths

def initPaths(dirs):

    try:
        # include <local> paths     NOTE: realpath() works with simlinks
        cmd_folder = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile(inspect.currentframe()))[0]))
        if cmd_folder not in sys.path:
            sys.path.insert(0, cmd_folder)

        # include dirs passed
        for dir in dirs:
            cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], dir)))
            if cmd_subfolder not in sys.path:
                sys.path.insert(0, cmd_subfolder)

    except Exception as e:
        pass

#--------------------------------------

def remove_comments(line, sep):
    for s in sep:
        i = line.find(s)
        if i >= 0:
            line = line[:i]
    return line.strip()

#--------------------------------------

def deviceJob(device, modImport, logger, options):

    try:
        client = clientDevice(logger, device, options)
        shell = LocalCmd(logger)
    
        module = modImport.ModuleRun(logger, device, options)
    
        logger.info('Entering Module : ' + options.moduleName)
        module.run(shell, client)
        logger.info('Exited Module : ' + options.moduleName)

    except Exception as err:
        device_ip = device[0]
        msg = "[" + device_ip + "] errors "
        logger.error(msg + ": %s " % str(err))

#--------------------------------------
# main

def main(argv):
    try:
        if len(argv) < 8:
            print usage()
            exit(1)

        currPath = os.getcwd()

        #------------------
        # get timestamp now
        nowTime = datetime.now().strftime("%Y-%m-%d_%H.%M.%S")

        #------------------
        # parse command line arguments
        parser = argparse.ArgumentParser(description='Run Device Manager', epilog="DeviceRunner", usage=usage())
        parser.add_argument('-m', '--module', help='Module to run', required=True)
        parser.add_argument('-u', '--username', help='Logon user name', required=True)
        parser.add_argument('-p', '--password', help='Password for logon', required=True)
        parser.add_argument('-r', '--remoteport', help='Remote port', required=True)
        parser.add_argument('-d', '--devices', help='Devuce IDs', required=True)

        try:
            #options = parser.parse_args()
            options, moduleArgs = parser.parse_known_args()
        except:
            print("Unable to parse command line arguments")
            exit(1)

        moduleName = options.module

        #------------------
        # initialize logging
        level = 'INFO'
        log_file = moduleName + '_' + nowTime + '.log'
        log_to_stdout = False

        options.moduleName = moduleName

        # init logger - refernece with module name
        logger = init_logger(log_file, level, log_to_stdout)

        # post app info in log
        logger.info('Device Manager version : ' + __VERSION__)

        #------------------
        # init command line handler
        shell = LocalCmd(logger)

        #------------------
        # include paths
        dirs = ['.', 'modules', 'Modules']
        initPaths(dirs)

        #------------------
        # verify module to run
        try:
            modImport = __import__(moduleName)
            module = modImport.Module()
        except Exception as e:
            msg = '\n\n'
            msg += 'Module : ' + moduleName + '\n'
            msg += '     msg : ' + e.msg + '\n'
            msg += 'lineno : ' + str(e.lineno)    + '\n'
            msg += 'offset : ' + str(e.offset) + '\n'
            msg += '    line : ' + e.text
            print ('Error importing module : ' + msg)
            logger.error('Error importing module : ' + msg)
            exit(1)

        logger.info('           module name : ' + module.name )
        logger.info('        module version : ' + module.version )
        logger.info('    module description : ' + module.description )
        logger.info('         Starting time : ' + nowTime )
        logger.info(' ----------------------------------------------------------')

        #------------------
        # parse module command line arguments
        parser = argparse.ArgumentParser(description='Run module', epilog="DeviceRunner", usage=module.using())
        parser = module.args(parser)
        try:
                options = parser.parse_args(moduleArgs, namespace=options)
        except:
                logger.error("Parse Error")
                exit(1)

        #------------------
        # run module pre_run to verify all dependencies
        # shell is only passed here becuase pre-run is a singleton and this shell is not thread safe
        ready = module.pre_run(shell, logger, options)
        if not ready:
            logger.error("Module dependencies not met")
            exit(1)

        #------------------
        queue = None
        sessions = []

        #------------------
        # identify devices
        
        # ipv4 check - need to include a better check
        ipPattern = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")

        devicesCLI = options.devices
        devices = []
        found = False

        # first check for devices on the command line
        for d in devicesCLI.split(','):
            if re.match(ipPattern, d):
                devices.append(d)
                found = True

        if not found:
            # IP on CLI not found, try intput file
            try:
                with open(d, mode='r') as fp:
                    a = fp.read()
                    b = a.splitlines()

                    for c in b:
                        c = remove_comments( c, '#' )

                        for d in c.replace(' ', '').split(','):
                            if re.match(ipPattern, d):
                                devices.append(d)
                                found = True
            except:
                found = False

        if not found:
            print "No valid devices found"
            usage()
            exit(1)

        #------------------
        # identify duplicates
        dups = list( set([x for x in devices if devices.count(x) > 1]) )
        if len(dups) > 0:
            print "Duplicates device(s) found: "
            print str(dups)
            exit(1)

        #--------------------------------------
        # configure processing

        if len(devices) == 1:
            _RUN_TYPE_ = _SEQUENTIAL_
        elif len(devices) < 8:
            _RUN_TYPE_ = _MULTITHREADED_
        else:
            _RUN_TYPE_ = _MULTIPROCESSOR_

        if _RUN_TYPE_ == _MULTIPROCESSOR_:
            from multiprocessing import Queue
            from Queue import Empty

            cpuCnt = multiprocessing.cpu_count()
            num_update_processors = cpuCnt
            queue_size = num_update_threads * (num_update_processors + 1)

        if _RUN_TYPE_ == _MULTITHREADED_:
            if sys.version_info[0] < 3:
                from Queue import Queue
                from Queue import Empty
            else:
                from queue import Queue
                from queue import Empty
            queue_size = num_update_threads * 2

        #------------------
        # Worker Threaded

        if _RUN_TYPE_ == _MULTITHREADED_:
            try:
                queue = Queue(queue_size)
                # Set up some threads to fetch the enclosures
                for i in range(num_update_threads):
                    t = wThead(logger, deviceJob, modImport, queue, options)
                    sessions.append(t)
                    t.start()

            except Exception as err:
                logger.error("Threading Error : " + str(err))
                sys.stderr.write(str(err))

        #------------------
        # Multiprocessor-Threaded

        if _RUN_TYPE_ == _MULTIPROCESSOR_:
            try:
                queue = multiprocessing.Queue(queue_size)

                for i in range(num_update_processors):
                    p = wProcess(logger, deviceJob, modImport, queue, options)
                    sessions.append(p)
                    p.start()

            except Exception as err:
                logger.error("Processing Error : " + str(err))
                sys.stderr.write(str(err))

        #------------------
        # dispatch job for each device
        for ip_addr in devices:
            # for now only ip address
            device = [ip_addr]

            # removing key reference here where it is thread safe
            remove_rsa_key(shell, ip_addr, options.remoteport)
            if _RUN_TYPE_ == _SEQUENTIAL_:
                # run serial
                deviceJob(device, modImport, logger, options)
            else:
                # run parallel
                queue.put(json.dumps({'device': device}))

        for s in sessions:
            s.join()

    except Exception as err:
        msg = "\nUnable to proceed: %s" % str(err)
        # try to log "Unable to proceed" message
        try:
            logger.error(msg)
        except Exception:
            pass
        raise Exception(err)

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as err:
        sys.stderr.write(str(err))
        sys.exit(1)



