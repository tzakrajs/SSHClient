# Copyright [2012] [Thomas Zakrajsek]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import paramiko
import re
import time
import os
import logging
from log import new_logger

"""This module implements the SSHShell class.

TODO(tzakrajsek): Timeouts on all commands sent to the shell

"""

class SSHShell(object):


    """Manipulates an interactive shell on a remote server with plenty of
    handy features that build on paramiko.

    """

    prompt = 'sshclient# '
    password_prompt = 'password: '
    verbose = False
    debug = False

    def __init__(self, host, un, pw, **kwargs):
        """Creates connection to the remote host and sets PS1 environment
        variable

        """
        try:
            port = kwargs['port']
        except Exception, e:
            port = 22
        try:
            private_key_path = kwargs['private_key_path']
        except Exception, e:
            private_key_path = None
        if private_key_path is not None:
            private_key_file = os.path.expanduser(private_key_path)
            private_key = paramiko.RSAKey.from_private_key_file(private_key_file)
        else:
            private_key = None

        if self.verbose:
            logger = new_logger('worker', 'debug')
        if self.debug:
            logger = new_logger('worker', 'info')
        else:
            logger = new_logger('worker', 'warning')

        self.logger = logging.getLogger('worker')
        self.logger.debug("Defaulting to port 22")
        (self.hostname, self.username, self.password) = (host, un, pw)
        if private_key is not None:
            ssh_password = None
        else:
            ssh_password = self.password
        self.logger.info("Connecting to %s@%s using pw: %s and key: %s" % \
                         (self.username, self.hostname,
                          ssh_password, private_key_path))
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.hostname, username=self.username,
                         password=ssh_password, port=port, pkey=private_key)
        self.shell = self.ssh.invoke_shell()
        self.set_prompt()

    def run_command(self, command, **kwargs):
        """Runs a command in the shell and returns the output of the
        command as a string

        """
        self.logger.info("Running command: %s" % command)
        self.shell.send('%s\n' % command)
        # Prompt does not include \r\n on this attempt, ran into issues in
        # certain circumstances
        (i, output_as_list) = self.ends_with([self.prompt],
                                             output=True)
        try:
            if kwargs['list'] is True:
                self.logger.debug('Returning output from command as list')
                return output_as_list
        except Exception:
            if self.debug is True:
                self.logger.debug('Returning output from command as string')
        output = ''
        for item in output_as_list:
            output += "%s\r\n" % item
        return output.rstrip('\r\n')

    def run_sudo(self, password):
        """Elevates the shell using sudo, uses predefined password if
        required

        """
        if password is not None:
            sudo_password = password
        else:
            sudo_password = self.password
        self.logger.info("Exporting EVs and running sudo bash --norc " \
                         "--noprofile")
        self.shell.send("export SUDO_PROMPT='%s' SUDO_PS1='%s'\n" % \
                        (self.password_prompt, self.prompt))
        buff = ''
        i = self.ends_with(['\r\n%s' % self.prompt])
        if i == 0:
            self.logger.info("Sending required password for sudo")
            self.shell.send('%s\n' % sudo_password)
            i = self.ends_with(['\r\n%s' % self.prompt])
            if i == 0:
                return True
        if i == 1:
            self.logger.info("Sudo password not required, skipping")
            return True 

    def su_to(self, username, password):
        """Switches to the specified user with the defined password"""
        self.logger.info("Switching to the %s user with password %s" % \
                         (username, password))
        su_command = "/bin/su -c '/bin/bash --norc --noprofile' %s\n" % \
                     username
        self.shell.send(su_command)
        i = self.ends_with(['assword: '])
        if i == 0:
            self.logger.info('Sending required password for su')
            self.shell.send('%s\n' % password)
            self.ends_with(self.prompt)

    def set_prompt(self):
        self.logger.info('Setting prompt to %s' % self.prompt)
        self.shell.send("export PS1='%s'\n" % self.prompt)
        i = self.ends_with(['\r\n%s' % self.prompt])

    def ends_with(self, possible_prompts, **kwargs):
        buff = ''
        beginning_time = time.time()
        while True:
            current_time = time.time()
            if current_time >= (beginning_time + 10.0):
                raise TimeoutException('Took longer than 10 seconds to get ' \
                                       'the prompt')
                break
            for id, prompt in enumerate(possible_prompts):
                if buff.endswith(prompt):
                    self.logger.debug('Prompt found')
                    try:
                        output = kwargs['output']
                    except:
                        output = False
                    if output:
                        buff_list = buff.splitlines()[1:]
                        buff_list.pop(-1)
                        return (id, buff_list)
                    else:
                        return id
            resp = self.shell.recv(9999)
            buff += resp

    def exists(self, path):
        test_path = 'test -e %s; echo $?' % path
        output = shell.run_command(test_path)
        if '0' in output:
            return True
        elif '1' in output:
            return False

    def create_file(self, path, data, **kwargs):
        try:
            clobber = kwargs['clobber']
        except:
            clobber = False
        file_exists = self.exists(path)
        if (file_exists and clobber is True) or self.exists(path) is False:
            create_file = "cat > %s <<EOF\n" % path
            shell.shell.send(create_file)
            i = shell.ends_with(['> ', shell.prompt])
            if i == 0:
                shell.shell.send(data + '\nEOF\n\n')
                i = shell.ends_with([shell.prompt])
                if i == 0:
                    self.logger.debug('Wrote file to disk.')
            output = self.run_command('echo $?')

        elif self.exists(path) and clobber is False:
            self.logger.warning('You may not overwrite the existing file.')

    def destroy(self):
        self.logger.info('Disconnecting from remote server')
        self.shell.send('exit\n')
        try:
            self.ssh.close()
        except NoneType:
            self.logger.warning('Cannot destroy SSH connection because it ' \
                                'has not yet been instantiated or has been ' \
                                'destroyed previously.')
