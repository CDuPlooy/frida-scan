# -*- coding: utf-8 -*-
from __future__ import print_function
import json

import threading

import frida
import argparse
from frida_tools.application import Reactor
from rich import print as pprint
from base64 import b64encode
from rich.progress import Progress
from pathlib import Path
import signal
import json

# How'd I do this in the past again???
signal.signal(signal.SIGINT, lambda x,y: exit(0))


parser = argparse.ArgumentParser(description='CLI memory scanner')
parser.add_argument('-p', dest='pid', type=str,
					help='The PID of the process to attach to, can also be a process name')
parser.add_argument('-pp', dest='page_protection', type=str, default='rw-',
					help='The protection attribute of pages to scan (\'r--\', \'rwx\')')
parser.add_argument('-d', dest='debugger', action='store_true',
					help='Enable the debugger')
parser.add_argument('-f', dest='target',
					help='Sets the name of the application to run')
parser.add_argument('-F', dest='foremost', action='store_true',
					help='Attach to the foremost application')
parser.add_argument('-U', dest='usb', action='store_true',
					help='If set establish a connection to the frida-server over USB')
parser.add_argument('-H', dest='host',
					help='If set establish a connection to the frida-server to <ip:port> or <ip>')
parser.add_argument('-l', dest='script',
					help='Loads a startup script before loading the normal agent')
# TODO: Child gating is probably not something that a memory scanner will ever need. 	
parser.add_argument('-c', dest='child_gating', action='store_true',
					help='When specified, child gating will be enabled',
					default=False)
parser.add_argument('-w', dest='window_size', type=str,
					help='The window size for debug printing ie 5:10 or 32',
					default="0:32")	
parser.add_argument('-ss', dest='search_string', type=str,
					help='The string to search for (does not take in any special parameters)',
					default=None)
parser.add_argument('-sn', dest='search_number', type=int,
					help='The number to search for',
					default=None)
parser.add_argument('-sp', dest='search_pattern', type=str,
					help='The pattern  to search for (AA BB ?? DD)',
					default=None)
parser.add_argument('-dd', dest='display_dump', action='store_true',
					help='When a pattern match is found, use the default frida hexdump',
					default=True)
parser.add_argument('-cstring', dest='display_string', action='store_true',
					help='Dump only the string match',
					default=False)
parser.add_argument('-dj', dest='display_json', type=str,
					help='Dump results as json',
					default=None)
parser.add_argument('-ds', dest='cstring', action='store_false',
					help='Dump cstrings only')
parser.add_argument('-ff', dest='filter_file', type=str,
					help='Exclude any ranges belonging to modules matching this list (comma separated)')
# TODO: Better to fix this later, maybe accumulate results to a string
# TODO: What about -i for include module in search, and -e for exclude
# TODO: Default is to include all? 
parser.add_argument('-j', dest='json', type=str,
					help='Dumps results to a JSON file instead of stdout')
parser.add_argument('-r', dest='range', type=str,
					help='Specified as <base_ptr:size>')
args = parser.parse_args()

if args.pid is None and args.target is None and args.foremost == False:
	print("Either -p/-f/-F must be specified!")
	exit(0)

if args.search_string is None and args.search_number is None and args.search_pattern is None:
	print("A search parameter must be specified!")
	exit(0)

script_source = None
script_dir = Path(__file__).parent.absolute()
with open(script_dir.joinpath("agent").joinpath("_agent.js"), "r", encoding='utf-8') as fd:
	script_source = fd.read()


window_size = args.window_size.split(':')
if len(window_size) != 2:
	if len(window_size) == 1:
		window_size_left = window_size_right = int(window_size[0])
	else:
		pprint('[red]Window size must be of the format left:right or int[/red]')
		exit(0)
else:
	window_size_left = int(window_size[0])
	window_size_right = int(window_size[1])


# Disables the default output if another mode is set
if args.display_string or args.display_json:
	args.display_dump = False

class Application(object):
	def __init__(self):
		self._stop_requested = threading.Event()
		self.resume_session = False	
		self._reactor = Reactor(
			run_until_return=lambda reactor: self._stop_requested.wait())

		if args.usb:
			self._device = frida.get_usb_device()
		elif args.host is not None:
			host = args.host
			if ":" in host:
				parts = host.split(":")
				ip = parts[0]
				port = parts[1]
			else:
				ip = host
				port = 27042
			self._device = frida.get_device_manager().add_remote_device(f'{ip}:{port}')
		else:
			self._device = frida.get_local_device()
		self._sessions = set()

		self._device.on(
			"child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))


	def run(self):
		self._reactor.schedule(lambda: self._start())
		self._reactor.run()

	def _start(self):
		self._instrument()

	def _stop_if_idle(self):
		if len(self._sessions) == 0:
			self._stop_requested.set()

	def _instrument(self):
		# if pid is a name -> get a pid
		if args.foremost:
			prog = self._device.get_frontmost_application()
			pprint(f"[green]Attaching to foremost [yellow]{prog}[/yellow][/green]")
			session = self._device.attach(prog.pid)
			pid = prog.pid
		elif args.pid is not None:
			strPid = str(args.pid)
			if strPid.isnumeric():
				pid = int(args.pid)
				session = self._device.attach(pid)
			else:
				processes = self._device.enumerate_processes()
				target = None
				for process in processes:
					if args.pid.lower() in process.name.lower():
						target = process
						break
				if target is None:
					pprint('[red]Unable to find specified process![/red]')
					exit(0)
				else:
					pprint(f'[green]Attaching to [yellow]{target}[/yellow][/green]')
					session = self._device.attach(target.pid)
					pid = target.pid
					self.resume_session = True
		# The last case just spawns the process for you
		else:
			pid = self._device.spawn(args.target)
			session = self._device.attach(pid)

		if args.debugger == True:
			session.enable_debugger()

		session.on("detached", lambda reason: self._reactor.schedule(
			lambda: self._on_detached(pid, session, reason)))
		if args.child_gating == True:
			session.enable_child_gating()
		script = session.create_script(script_source)
		script.on("message", lambda message, data: self._reactor.schedule(
			lambda: self._on_message(pid, message)))
		script.load()

		# TODO: Eventually we'll want to replace the hexdump with something python specific
		api = script.exports
		if self.resume_session:
			session.resume()
		else:
			self._device.resume(pid)
		self._sessions.add(session)
		
		ranges = api.enumerate_memory_ranges(args.page_protection)
		is_raw_pattern = args.search_pattern is not None
		if args.search_string is not None:
			patternType = 'string'
			pattern = args.search_string 
		elif args.search_number is not None:
			patternType = 'number'
			pattern = args.search_number
		else:
			patternType = 'raw'
			pattern = args.search_pattern

		with Progress() as progress:
			jsonData = []
			task = progress.add_task(f"[bold purple]Scanning pid[{pid}]...", total=len(ranges))
			for r in ranges:
				results = api.scan_range(pattern, r, is_raw_pattern)

				for result in results:
					address = int(result['address'], 16)
					result['pid'] = pid
					start_address = address - window_size_left
					end_address = address + window_size_right
					address_window_size = end_address - start_address
					if args.display_dump:
						print(api.hex_dump(start_address, address_window_size))
					elif args.cstring:
						print(api.read_c_string(address))
					elif args.display_string:
						print(f'Match found for pattern at {result["address"]}' )
					elif args.display_json:
						result['data'] = b64encode(api.read_byte_array(address, address_window_size)).decode()
						jsonData.append(result)
				progress.update(task, advance=1)
		
		if args.display_json:
			with open(args.display_json, 'w') as fd:
				json.dump({"matches": jsonData, "patternType": patternType, "pattern": pattern}, fd)
			pprint(f'JSON dumped to [yellow]{args.display_json}[/yellow]')
		pprint(f'[green]Done with pid[{pid}][/green]')
		self._on_detached(pid, session, "done")


	def _on_child_added(self, child):
		self._instrument(child.pid)

	def _on_detached(self, pid, session, reason):
		if session is not None:
			self._sessions.remove(session)
		self._reactor.schedule(self._stop_if_idle, delay=0.25)

	def _on_message(self, pid, message):
		print(" message: pid={}, payload={}".format(pid, message["payload"]))


app = Application()
app.run()

# 1 TODO: Test if the script is correctly executed 
# this should include usb, local and network connections

# 2 TODO: Get the basic functionality working (ie perform a memory scan using this)

# 3 TODO: Implement all other flags