#!/usr/bin/env python3

import json
import shlex
import subprocess

import looseversion

def govulncheck():
  findings = []
  cmd = ['govulncheck', '-json', './...']
  print('+ ' + shlex.join(cmd))
  check = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=0)
  json_lines = []
  while True:
    line = check.stdout.readline()
    if not line:
      break
    line = line.rstrip()
    json_lines.append(line)
    if line == b'}':
      j = json.loads(b''.join(json_lines))
      json_lines = []
      if 'config' in j:
        print('Running {scanner_name} {scanner_version} '
              'using {db} @ {db_last_modified}'.format(**j['config']))
      if 'progress' in j:
        print(j['progress']['message'])
      if 'finding' in j:
        findings.append(j['finding'])
  if check.wait() != 0 or json_lines:
    return None
  return findings

def run_ext(*cmd):
  print('+ ' + shlex.join(cmd))
  subprocess.run(cmd)

def run_once():
  findings = govulncheck()
  if not findings:
    return True
  modules = {}
  for finding in findings:
    if finding.get('trace'):
      trace = finding['trace'][0]
      mod = modules.setdefault(trace['module'], (set(), set(), set()))
      mod[0].add(trace['version'])
      mod[1].add(finding['fixed_version'])
      mod[2].add(finding['osv'])
  for mod, patch in modules.items():
    av, fv, desc = map(list, patch)
    av.sort(key=looseversion.LooseVersion)
    fv.sort(key=looseversion.LooseVersion)
    desc.sort()
    print('{} ({}) => ({})'.format(mod, ', '.join(av), ', '.join(fv)))
    while desc:
      print('  {}'.format(', '.join(desc[:5])))
      desc = desc[5:]
    run_ext('go', 'get', '{}@{}'.format(mod, fv[-1]))
  run_ext('go', 'mod', 'tidy')
  run_ext('go', 'mod', 'vendor')

def govulnbump():
  run_ext('go', 'mod', 'tidy')
  run_ext('go', 'mod', 'vendor')
  while not run_once():
    pass

if __name__ == '__main__':
  govulnbump()
