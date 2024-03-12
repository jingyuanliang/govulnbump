#!/usr/bin/env python3

import argparse
import json
import os
import re
import shlex
import subprocess

import looseversion

def govulncheck(db):
  findings = []
  cmd = ['govulncheck', '-json']
  if db:
    cmd += ['-db', db]
  cmd.append('./...')
  print('+ ' + shlex.join(cmd))
  env = dict(os.environ)
  env['CGO_ENABLED'] = '0'
  check = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, bufsize=0)
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
    raise subprocess.CalledProcessError(check.returncode, cmd)
  return findings

def run_ext(*cmd):
  print('+ ' + shlex.join(cmd))
  subprocess.run(cmd).check_returncode()

def run_once(db):
  findings = govulncheck(db)
  modules = {}
  for finding in findings:
    if finding.get('trace'):
      trace = finding['trace'][0]
      if not trace.get('function'):
        continue
      mod = modules.setdefault(trace['module'], (set(), set(), set()))
      mod[0].add(trace['version'])
      mod[1].add(finding['fixed_version'])
      mod[2].add(finding['osv'])
  fresh = True
  for mod, patch in modules.items():
    if mod == 'stdlib':
      continue
    av, fv, desc = map(list, patch)
    av.sort(key=looseversion.LooseVersion)
    fv.sort(key=looseversion.LooseVersion)
    desc.sort()
    print('{} ({}) => ({})'.format(mod, ', '.join(av), ', '.join(fv)))
    while desc:
      print('  {}'.format(', '.join(desc[:5])))
      desc = desc[5:]
    if fresh:
      run_ext('go', 'get', '{}@{}'.format(mod, fv[-1]))
      fresh = False
    else:
      print('  Not bumping now to avoid unexpected downgrading.')
  if fresh:
    return True
  run_ext('go', 'mod', 'tidy')
  run_ext('go', 'mod', 'vendor')

def govulnbump(db=None):
  run_ext('go', 'mod', 'tidy')
  run_ext('go', 'mod', 'vendor')
  while not run_once(db):
    pass
  with open('go.mod', 'r') as f:
    gomod = f.read()
  gomod = re.sub(r'\n+toolchain .+\n+', '\n\n', gomod)
  with open('go.mod', 'w') as f:
    f.write(gomod)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--db')
  args = parser.parse_args()
  govulnbump(db=args.db)

if __name__ == '__main__':
  main()
