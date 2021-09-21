# ------------------------------------------------------------------------
#Copyright 2021 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
# ------------------------------------------------------------------------

import argparse
import datetime
import logging
import os
import re
import subprocess
import sys
import tarfile
import sqlite3


class LogParser():
  """Parse Pacemaker logs and generate output of critical events.

  Attributes:
    date_begin: String for begin timestamp for time range analysis
    date_end: String for end timestamp for time range analysis
    system_log: List of strings for system logs
    pacemaker_log: List of strings for pacemaker logs
    hb_report: String for hb_report name
    sosreport: List of strings for sosreports
    output_file: String for output file name
    open_file: Boolean to open the output file with default program
    debug: Boolean to list debug info
    pacemaker_log_keywords: String for keywords to filter pacemaker logs
    system_log_keywords: String for keywords to filter system logs
    conn: DB connection to temp in memory DB
    sql_query: String for SQL to select critical events
  """

  def __init__(self, variables):

    # init logging
    loglevel = logging.DEBUG if variables.d else logging.INFO
    logging.basicConfig(
        level=loglevel,
        format='%(asctime)s - %(message)s',
        handlers=[logging.StreamHandler()])

    # validate arguments
    if (variables.s is None and variables.p is None and variables.hb is None and
        variables.sos is None):
      logging.info('Please specify at least one file to parse.')
      sys.exit()

    if variables.b:
      self.date_begin = self.format_timestamp_from_timeinput(variables.b[0])

    if variables.e:
      self.date_end = self.format_timestamp_from_timeinput(variables.e[0])

    if (variables.b and variables.e):
      if self.date_end <= self.date_begin:
        logging.info(
            'Begin time is equal or later than end time, please correct.')
        sys.exit()

    if variables.s:
      if len(variables.s) > 2:
        logging.info('Please input max two system logs from two nodes.')
        sys.exit()

    if variables.p:
      if len(variables.p) > 2:
        logging.info('Please input max two pacemaker logs from two nodes.')
        sys.exit()
    
    if variables.hb:
      if len(variables.hb) > 2:
        logging.info('Please input max two hb_report from two nodes.')
        sys.exit()

    if variables.sos:
      if len(variables.sos) > 2:
        logging.info('Please input max two sosreport from two nodes.')
        sys.exit()

    self.pacemaker_log_keywords = (
        'LogAction|LogNodeActions|stonith-ng|pacemaker-fenced|crit:|check_migration_threshold|corosync|Result'
        ' of|reboot|cannot run anywhere|attrd_peer_update|High CPU load detected|cli-ban|cli-prefer'
        'cib-bootstrap-options-maintenance-mode|-is-managed|-maintenance|-standby')
    self.system_log_keywords = (
        r'SAPHana\(|SAPHanaController\(|SAPHanaTopology\(|SAPInstance\(|gcp-vpc-move-vip|gcp:alias|gcp:stonith|fence_gce|corosync\[|Result'
        ' of|reboot')

    # Generate the big sql query
    time = ''
    table = 'log'
    # Generate the string to filter column TIME
    if variables.b:
      time = 'WHERE TIME > \'' + str(self.date_begin) + '\''
      if variables.e:
        time += ' AND TIME < \'' + str(self.date_end) + '\''
    elif variables.e:
      time = 'WHERE TIME < \'' + str(self.date_end) + '\''

    sql = []
    statement = 'SELECT TIME, NODE, COMPONENT, PAYLOAD FROM('
    if time:
      statement += (
          'WITH data as (SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD '
          'FROM log ') + time + ') '
      table = 'data'
    # Fencing actions & results, stonith timeout
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE PAYLOAD LIKE '%$*%FENCE%' ESCAPE '$' OR PAYLOAD LIKE '%remote_op_done%Operation%' OR PAYLOAD LIKE '%monitor%Timer%expired%'"
    )
    # Pacemaker actions for resources, CRMD critical logs, high CPU load
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE PAYLOAD LIKE '%notice%LogAction%' OR PAYLOAD LIKE '%(LogAction)%' OR PAYLOAD LIKE '%crit:%' OR PAYLOAD LIKE '%Forcing%away%' OR PAYLOAD LIKE '%cannot%run%anywhere%' or PAYLOAD LIKE '%attrd_peer_update%INFINITY%' OR PAYLOAD LIKE '%CPU%detected%'"
    )
    # Corosync error or membership change
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE PAYLOAD LIKE '%TOTEM%' AND (PAYLOAD LIKE '%failed%' OR PAYLOAD LIKE '%membership%' OR PAYLOAD LIKE '%Retransmit%')"
    )
    # Failed resource operations
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE PAYLOAD LIKE '%Result%of%operation%' AND PAYLOAD NOT LIKE '%ok%' AND PAYLOAD NOT LIKE '%Cancelled%' AND PAYLOAD NOT LIKE '%probe%'"
    )
    # SAPInstance, gcp:stonith, gcp:alias, gcp-vpc-move-vip,fence_gce error
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE (COMPONENT LIKE 'SAPInstance%' OR COMPONENT in ('stonith-ng', 'gcp:stonith','gcp:alias','gcp-vpc-move-vip','fence_gce')) AND (PAYLOAD LIKE '%ERROR%' or PAYLOAD LIKE '%Failed%')"
    )
    # SAPHANA error or warning
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE COMPONENT LIKE 'SAPHana%' AND (PAYLOAD LIKE '%ERROR:%' OR PAYLOAD LIKE '%WARNING:%' or PAYLOAD LIKE '%ACT%SFAIL%')"
    )
    # Cluster/Node/RSC maintenance/standby/manage mode change
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE PAYLOAD LIKE '%cib-bootstrap-options-maintenance-mode%value%' OR PAYLOAD LIKE '%cib_perform_op%nodes-%-maintenance%' or PAYLOAD LIKE '%cib_perform_op%nodes-%-standby%' or PAYLOAD LIKE '%cib_perform_op%meta_attributes-%'"
    )
    # Location constaint cli-ban or cli-perfer due to manual resource movement
    sql.append(
        'SELECT rowid, TIME, NODE, COMPONENT, PAYLOAD FROM ' + table +
        " WHERE PAYLOAD LIKE '%cli-ban%' OR PAYLOAD LIKE '%cli-prefer%'"
    )

    # Assemble the SQL
    statement = statement + ' UNION '.join(sql) + ' ORDER BY TIME, rowid)'

    self.sql_query = statement
    self.system_log = variables.s
    self.pacemaker_log = variables.p
    self.hb_report = variables.hb
    self.SOSREPORT = variables.sos
    self.debug = variables.d
    self.output_file = variables.o
    self.open_file = variables.x

    # Create an in-memory DB and a table 'log'
    try:
      self.conn = sqlite3.connect(':memory:')
      self.conn.execute(
          'CREATE TABLE log (TIME TEXT, NODE TEXT, COMPONENT TEXT, PAYLOAD TEXT)')
      self.conn.commit()
    except sqlite3.Error as err:
      logging.error('Error creating the DB and table: %s.', str(err))
      sys.exit()

  def logparser(self):
    """Call individual functions to parse the logs.

    Raises:
      sqlite3.Error: An error occurred when querying the DB table
    """
    logging.info('Starting the log parser.')

    if self.system_log:
      self.logfile_parser(self.system_log, 's')
    if self.pacemaker_log:
      self.logfile_parser(self.pacemaker_log, 'p')
    if self.hb_report:
      self.hb_report_parser(self.hb_report[0])
    if self.SOSREPORT:
      self.sosreport_parser(self.SOSREPORT)
    if self.output_file:
      self.generate_output(self.output_file[0])
      if self.open_file:
        subprocess.call(['open', self.output_file[0]])
    else:
      self.generate_output()
      if self.open_file:
        subprocess.call(['open', 'logparser.out'])

    try:
      cursor = self.conn.execute('SELECT distinct COMPONENT FROM log')
      logging.debug('All components parsed:')
      for row in cursor:
        logging.debug('  %s', row[0])

      cursor = self.conn.execute('SELECT distinct NODE FROM log')
      logging.debug('All nodes parsed:')
      for row in cursor:
        logging.debug('  %s', row[0])
    except sqlite3.Error as err:
      logging.error('Error generating debug info: %s.', str(err))

    self.cleanup()

  def logfile_parser(self, files, log_type):
    """Loop each log file and parse each log line.

    Args:
      files: List of strings for log file names
      log_type: String for type of log files, 'p' for pacamker logs, 's' for system logs

    Raises:
      OSError: An error occurred when opening the log file
    """
    for log in files:
      try:
        with open(log, 'r', errors='replace') as inputfile:
          logging.info('Parsing %s.', log)
          line = inputfile.readline()
          while line:
            self.parse_log_line(line, log_type)
            line = inputfile.readline()
      except OSError:
        logging.error('Cannot find/open/read file: %s.', log)

  def hb_report_parser(self, file):
    """Parse hb_report in format tar.gz.

    Extract the two cluster nodes from member.txt. If the file doesn't exist,
    extract from description.txt. Then use the node name to go to individual
    folder to parse pacemaker.log and messages. If messages is missing, parse
    journal.log

    Args:
      file: String for hb_report name

    Raises:
      ReadError: An error occured when opening the tar file
      FileNotFoundError: An error occured when the tar file doesn't exist
      KeyError: An error occured when the file to extract was missing
    """
    try:
      t = tarfile.open(file, 'r')
    except tarfile.ReadError:
      logging.error('Cannot read the file %s. '
                    'Please manually extract the logs and parse them.', file)
      sys.exit()
    except FileNotFoundError:
      logging.error('Cannot find the file %s. ', file)
      sys.exit()
    else:
      members = []
      with t:
        # Get the node names from members.txt
        try:
          folder = os.path.commonprefix(t.getnames())
          members = t.extractfile(f'{folder}/members.txt').readline().decode('utf-8').split()
        except KeyError:
          logging.info('members.txt is missing.')

        # Get the node names from description.txt if members.txt is missing
        if not members:
          try:
            description = t.extractfile(f'{folder}/description.txt')
            description_line = description.readline().decode('utf-8')
            while description_line:
              if re.search('^(?!#####)System info', description_line):
                members.append(description_line.split(' ').pop().strip(':\n'))
              description_line = description.readline().decode('utf-8')
          except KeyError:
            logging.info(
                'description.txt is missing, not able to identify cluster nodes'
                '. Please manually extract the logs and parse them.')
            sys.exit()

        for member in members:
          logging.info('Found node %s in %s.', member, file)
          # Parse pacemaker.log
          if not self.compressed_file_parser(t, [folder, member, 'pacemaker.log'], 'SLES', 'p'):
            self.compressed_file_parser(t, [folder, member, 'corosync.log'], 'SLES', 'p')
          # Parse system log /var/log/messages or jounal.log
          if not self.compressed_file_parser(t, [folder, member, 'messages'], 'SLES', 's'):
            self.compressed_file_parser(t, [folder, member, 'journal.log'], 'SLES', 's')

  def compressed_file_parser(self, file_handle, path, distro, log_type):
    """Extract log file and parse each log line.

    Args:
      file_handle: File handle of the extracted hb_report
      path: List of strings for the path
      distro: String for os RHEL or SLES
      log_type: String for type of log files, 'p' for pacamker logs, 's' for system logs

    Returns:
      Boolean whether the file is successfully parsed.

    Raises:
      KeyError: An error occured when the file to extract was missing
    """
    if distro == 'SLES' and len(path) == 3:
      try:
        extractedfile = file_handle.extractfile(f'{path[0]}/{path[1]}/{path[2]}')
        logging.info('Parsing %s from node %s.', path[2], path[1])
        line = extractedfile.readline().decode('utf-8')
        while line:
          self.parse_log_line(line, log_type)
          line = extractedfile.readline().decode('utf-8')
        return True
      except KeyError:
        logging.info('%s not found for node %s.', path[2], path[1])
        return False

    if distro == 'RHEL' and len(path) == 2:
      try:
        extractedfile = file_handle.extractfile(f'{path[0]}/{path[1]}')
        logging.info('Parsing %s.', path[1])
        line = extractedfile.readline().decode('utf-8')
        while line:
          self.parse_log_line(line, log_type)
          line = extractedfile.readline().decode('utf-8')
        return True
      except KeyError:
        logging.info('%s not found in sosreport.', path[1])
        return False

  def sosreport_parser(self, filelist):
    """Parse sosreport in format tar.xz.

    1. Extract etc/os_release to get RHEL release
    2. If 7.x, parse /var/log/messages and /var/log/cluster/corosync.log
       If 8.x, parse /var/log/messages and /var/log/pacemaker/pacemaker.log

    Args:
      filelist: List of strings for sosreport names

    Raises:
      ReadError: An error occured when opening the tar file
      FileNotFoundError: An error occured when the tar file doesn't exist
      KeyError: An error occured when the file to extract was missing
    """
    for file in filelist:
      try:
        t = tarfile.open(file, 'r')
      except tarfile.ReadError:
        logging.error(
            'Cannot read the file %s. '
            'Please manually extract the logs and parse them.', file)
        sys.exit()
      except FileNotFoundError:
        logging.error('Cannot find the file %s. ', file)
        sys.exit()
      else:
        with t:
          try:
            os_ver = 0
            folder = os.path.commonprefix(t.getnames())
            osfile = t.extractfile(f'{folder}/etc/os-release')
            line = osfile.readline().decode('utf-8')
            while line:
              if re.search('VERSION_ID', line):
                os_ver = line.split('\"')[1]
                break
              line = osfile.readline().decode('utf-8')
          except KeyError:
            logging.info('etc/os-release is missing.')

          logging.info('Parsing %s.', file)
          if float(os_ver) >= 8:
            self.compressed_file_parser(t, [folder, 'var/log/messages'], 'RHEL', 's')
            self.compressed_file_parser(t, [folder, 'var/log/pacemaker/pacemaker.log'], 'RHEL', 'p')
          else:
            self.compressed_file_parser(t, [folder, 'var/log/messages'], 'RHEL', 's')
            self.compressed_file_parser(t, [folder, 'var/log/cluster/corosync.log'], 'RHEL', 'p')

  def generate_output(self, output='logparser.out'):
    """Write all critical events to output file.

    Execute the sql in the temp in memory DB and write the result set to output file.

    Args:
      output: String of outoput file name, default is 'logparser.out'

    Raises:
      sqlite3.Error: An error occurred when querying the DB table
    """
    try:
      cursor = self.execute_sql(self.sql_query, 's')
    except sqlite3.Error as err:
      logging.error('Error executing the big query: %s.', str(err))
      sys.exit()

    with open(output, 'w') as out:
      for row in cursor:
        out.writelines(' '.join(map(str, row)))
    logging.info('Please check output in file %s.', output)

  def execute_sql(self, sql, input_type):
    """Execute sql from string or file.

    Args:
      sql: String for sql or file name contains the sql
      input_type: String for input type. 's' for sql string, 'f' for file contains the sql string

    Returns:
      DB cursor of result set

    Raises:
      sqlite3.Error: An error occurred when querying the DB table
    """
    cursor = self.conn.cursor()
    if input_type == 's':
      try:
        return cursor.execute(sql)
      except sqlite3.Error as err:
        logging.error('Error in query: %s.', str(err))
        sys.exit()
    elif input_type == 'f':
      try:
        with open(sql) as sql_file:
          query = sql_file.read()
      except OSError:
        logging.error('Cannot find/open/read file: %s.', sql)
        sys.exit()
      try:
        return cursor.execute(query)
      except sqlite3.Error as err:
        logging.error('Error in query: %s.', str(err))
        sys.exit()
    else:
      logging.error('No such sql input type %s.', input_type)
      sys.exit()

  def parse_log_line(self, logline, logtype):
    """Format the timestamp in log line.

    Filter log lines by key words depend on log file type. 
    Insert the lines into the temp in memory DB.

    Args:
      logline: String for log line
      logtype: String for log type, 's' for system log, 'p' for pacemaker log
    """
    if logtype == 's':
      pattern = self.system_log_keywords
    elif logtype == 'p':
      pattern = self.pacemaker_log_keywords
    else:
      logging.error('No such log type %s.', logtype)
      sys.exit()

    if re.search(pattern, logline):
      # Remove '[number]'
      logline = re.sub(r'\[\d*\]', '', logline, 1)
      timestamp = self.format_timestamp_from_logline(logline)
      if timestamp:
        if timestamp[1] == 1:
          # Split the line into 4 components:
          # timestamp, host, component, PAYLOAD
          newline = re.split(r'\s+', logline, 5)
          record = [str(timestamp[0]), newline[3], newline[4].strip(':').strip('/'), newline[5]]
        elif timestamp[1] == 2:
          # Split the line into 4 components:
          # timestamp, host, component, PAYLOAD
          newline = re.split(r'\s+', logline, 3)
          record = [str(timestamp[0]), newline[1], newline[2].strip(':').strip('/'), newline[3]]
        self.conn.execute('INSERT INTO log VALUES (?,?,?,?)', record)
        self.conn.commit()

  def format_timestamp_from_logline(self, line):
    """Format the timestamp in log line.

    Args:
      line: String for long line

    Returns:
      Formatted timestamp

    Raises:
      ValueError: An error occured when formatting the timestamp
    """
    # time format Nov 22 00:00:00
    time_format1 = [r'\w{3}\s+\d+\s\d\d:\d\d:\d\d', '%Y %b %d %H:%M:%S']
    # time format 2020-11-22T00:00:00
    time_format2 = [r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d', '%Y-%m-%dT%H:%M:%S']

    ts1 = re.search(time_format1[0], line)
    ts2 = re.search(time_format2[0], line)
    try:
      if ts1:
        return [
            datetime.datetime.strptime(
                str(datetime.datetime.now().year) + ' ' + ts1.group(),
                time_format1[1]), 1
        ]
      elif ts2:
        return [datetime.datetime.strptime(ts2.group(), time_format2[1]), 2]
      else:
        pass
    except ValueError:
      logging.error('Timestamp formatting failed.%s.', line)
      sys.exit()

  def format_timestamp_from_timeinput(self, time):
    """Format the timestamp in input argument.

    Args:
      time: String for input timestamp

    Returns:
      Formatted timestamp

    Raises:
      ValueError: An error occured when formatting the timestamp
    """
    # accepted timestamp format YYYY-MM-DD-HH:MM or YYYY-MM-DD
    pattern_format_list = [[r'\d{4}-\d\d-\d\d-\d\d:\d\d', '%Y-%m-%d-%H:%M'],
                           [r'\d{4}-\d\d-\d\d', '%Y-%m-%d']]
    for pair in pattern_format_list:
      if re.search(pair[0], time):
        try:
          return datetime.datetime.strptime(time, pair[1])
        except ValueError:
          logging.info('Timestamp %s formatting failed.', time)
          sys.exit()
    logging.info('Timestamp format needs to be YYYY-MM-DD-HH:MM or YYYY-MM-DD.')
    sys.exit()

  def cleanup(self):
    self.conn.close()


def main():
  parser = argparse.ArgumentParser(description='Pacemaker logs auto analyzer')
  parser.add_argument(
      '-p',
      metavar='pacemakerlog',
      help='Specify one or two pacemaker logs',
      nargs='+')
  parser.add_argument(
      '-s',
      metavar='syslog',
      help='Specify one or two system logs (/var/log/messages or journal.log)',
      nargs='+')
  parser.add_argument(
      '-hb',
      metavar='hb_report.tar.bz2',
      help='Specify hb_report',
      nargs='+')
  parser.add_argument(
      '-sos',
      metavar='sosreport.tar.xz',
      help='Specify one or two sosreport',
      nargs='+')
  parser.add_argument(
      '-b',
      metavar='BeginTime',
      help='Specify begin timestamp in format YYYY-MM-DD-HH:MM or YYYY-MM-DD',
      nargs=1)
  parser.add_argument(
      '-e',
      metavar='EndTime',
      help='Specify end timestamp in format YYYY-MM-DD-HH:MM or YYYY-MM-DD',
      nargs=1)
  parser.add_argument(
      '-o', metavar='output_file',
      help='Specify output file name, by default output file is logparser.out',
      nargs=1)
  parser.add_argument('-d', help=argparse.SUPPRESS, action='store_true')
  parser.add_argument('-x', help=argparse.SUPPRESS, action='store_true')

  # validate the arguments
  if len(sys.argv) == 1:
    parser.print_help()
    exit()
  args = parser.parse_args()

  pacemaker_parser = LogParser(args)
  pacemaker_parser.logparser()

if __name__ == '__main__':
  main()