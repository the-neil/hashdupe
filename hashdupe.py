#!/usr/bin/env python
'''
hashdupe.py
Neil // 2014-10-03
'''

from __future__ import print_function

import sys
import os
import argparse
import hashlib
import subprocess
import shutil
from pprint import pprint

try:
	from IPython import embed
except:
	def embed():
		pass

def main():
	parser = argparse.ArgumentParser(description="Recursively hash one or more directories to find duplicate files.")
	parser.add_argument('directories', metavar='dir', type=str, nargs='+', help="a directory to process")
	parser.add_argument('--algorithm', '-a', type=str, choices=('md5', 'sha256', 'ext-md5', 'openssl-ripemd160', 'openssl-whirlpool'), default='md5', help='which method to use to generate hashes')
	parser.add_argument('--print-all', '-pa', action='store_true', default=False, help="print out all hashes and their associated files")
	parser.add_argument('--print-uniques', '-pu', action='store_true', default=False, help="only show unique files")
	parser.add_argument('--print-duplicates', '-pd', action='store_true', default=False, help="only show duplicate files")
	parser.add_argument('--delete', '-d', action='store_true', default=False, help="delete all duplicate files except the first one found")
	parser.add_argument('--move', '-m', action='store', metavar='root', default=False, help="move all duplicate files except the first one to a tree rooted at the specified directory")
	# Debug Arguments Begin
	parser.add_argument('--debug-arguments', action='store_true', default=False, help=argparse.SUPPRESS)
	parser.add_argument('--debug-preprocess-index', action='store_true', default=False, help=argparse.SUPPRESS)
	# Debug Arguments End
	args = parser.parse_args()
	
	if args.delete and args.move:
		raise Exception("Error: If you --delete the files, you can't --move them. Pick one.")
	if args.print_all and (args.print_uniques or args.print_duplicates):
		sys.stderr.write("Warning: --print-all completely encompasses all other --print flags.")
	if args.print_uniques and args.print_duplicates:
		sys.stderr.write("Warning: using both --print-uniques and --print-duplicates is effectively --print-all.")
	
	if args.debug_arguments:
		pprint(args)
	
	index = dict()
	
	for directory in args.directories:
		for root, dirs, files in os.walk(directory):
			for d in dirs:
				pass
			for f in files:
				filepath = os.path.join(root, f)
				key = hash_file(args.algorithm, filepath)
				if key in index:
					index[key].append(filepath)
				else:
					index[key] = [filepath]
	
	if args.debug_preprocess_index:
		pprint(index)

	process_index(args, index)

def hash_file(algorithm, filepath):
	# If you would like to add another hashing algorithm, do the following:
	# 1. Pick a new string to name the option, and add it
	#    (a) above in the "--algorithm" argparse add_argument line and
	#    (b) in the below pseudo-switch statement.
	# 2. In the pseudo-switch statement, write whatever code is necessary
	#    to place just the hash as a string in the variable "key".
	if algorithm == 'ext-md5':
		if not os.path.exists('/sbin/md5'):
			raise Exception("Error: /sbin/md5 does not exist.")
		key = subprocess.check_output(['/sbin/md5', '-q', filepath]).strip().decode()
	elif algorithm == 'openssl-ripemd160':
		if not os.path.exists('/usr/bin/openssl'):
			raise Exception("Error: /usr/bin/openssl does not exist.")
		output = subprocess.check_output(['/usr/bin/openssl', 'dgst', '-ripemd160', filepath])
		key = output.strip().decode().split('= ')[1]
	elif algorithm == 'openssl-whirlpool':
		if not os.path.exists('/usr/bin/openssl'):
			raise Exception("Error: /usr/bin/openssl does not exist.")
		output = subprocess.check_output(['/usr/bin/openssl', 'dgst', '-whirlpool', filepath])
		key = output.strip().decode().split('= ')[1]
	elif algorithm == 'md5':
		handle = open(filepath, 'rb')
		algo = hashlib.md5()
		algo.update(handle.read())
		key = algo.hexdigest()
	elif algorithm == 'sha256':
		handle = open(filepath, 'rb')
		algo = hashlib.sha256()
		algo.update(handle.read())
		key = algo.hexdigest()
	else:
		raise Exception("Error: Unknown hashing algorithm chosen.")
	return key

def process_index(args, index):
	sortedkeys = sorted(index.keys(), key=lambda k: index[k][0])
	for key in sortedkeys:
		if (args.print_all or args.print_uniques or args.print_duplicates):
			print("Key:", key)
		if (args.print_all or args.print_uniques) and len(index[key]) <= 1:
			for path in index[key]:
				print("\tFile:", path)
		if (args.print_all or args.print_duplicates) and len(index[key]) > 1:
			for path in index[key]:
				print("\tFile:", path)
		
		if args.delete:
			duplicate_list = index[key][1:]
			for dead_man_walking in duplicate_list:
				print("\tDeleting:", dead_man_walking)
				os.remove(dead_man_walking)
		
		if args.move:
			duplicate_list = index[key][1:]
			for old_path in duplicate_list:
				new_path = os.path.abspath(os.path.join(args.move, old_path))
				print("\tMoving:\t{} -> {}".format(old_path, new_path))
				os.makedirs(os.path.dirname(new_path))
				shutil.move(old_path, new_path)



if __name__ == '__main__':
	main()

