# Name: compositor.py
# Desc: Composites information about user login information
# Usage: can be used on a live system or an image
# Date: 04/18/2018

'''Things Needed:
+ Time user logged in
+ How long logged in
+ Files created by user (hidden and non-hidden)
- Last access time of files (what files? All? or Some?)
- If user is in sudoers
+ Any symbolic links created (Should be taken care of in all files)
+ Hash all files created/accessed and send to VirusTotal

Options:
-d: directory to search from (Default: /)
-u: username
'''


import os
import sys
import pwd
import datetime
import hashlib
import requests
import subprocess

def get_hash(filePath):
	with open(filePath, 'rb') as open_file:
		m = hashlib.md5()
		content = open_file.read()
		m.update(content)
	return m.hexdigest()
	
def VT_request(hash):
	api_key = '761a1a2037feb740a3323ff5f556a873e50669ceed3d2df71a195042703aaa5a'
	params = {'apikey': api_key, 'resource': hash}
	url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	json_response = url.json()
	print json_response
	response = int(json_response.get('response_code'))
	if response == 1:
		positives = int(json_response.get('positives'))
		if positives == 0:
			return 'negative'
		else:
			return 'positive'

#Need to add information to check if sudo group is a part of /etc/sudoers
def is_sudoer(username):
	cmd = "groups " + username
	g = subprocess.check_output(cmd, shell=True)
	groups = g.split()
	for group in groups:
		if group == "sudo":
			return True
	return False

def create_output(user, dir, d_t, len_log, hashes, vt):
	now = datetime.datetime.now()
	with open('composite.txt', 'a') as output:
		output.write("Time of Tool Run: " + str(now) + "\n")
		output.write("User of Interest: " + user + "\n")
		output.write("Root Directory for Search: " + dir + "\n")
		output.write("User's Last Logon Time: " + str(d_t) + "\n")
		output.write("Duration of Last Logon: " + str(len_log) + "\n")
		output.write("User in Sudoers: " + str(is_sudoer(user)) + "\n")
		output.write("Hashes of User Files:\n")
		output.write('\n'.join('{} {}'.format(h[0],h[1]) for h in hashes))
		output.write('\n')
#		output.write("Malicious Files According to VirusTotal:\n")
#		output.write('\n'.join('{} {}'.format(v[0],v[1]) for v in vt))
		
def main():
	directory = '/'
	username = ''
	if len(sys.argv) != 3 and len(sys.argv) != 5:
		print("Usage: <command>.py -u <username> [-d <directory>]")
		exit()
	if len(sys.argv) == 3:
		if sys.argv[1] == "-u":
			username = sys.argv[2]
		else:
			print("Usage: <command>.py -u <username> [-d <directory>]")
			exit()
	if len(sys.argv) == 5:
		if sys.argv[1] == "-u":		
			username = sys.argv[2]
			if sys.argv[3] == "-d":
				directory = sys.argv[4]
		elif sys.argv[1] == "-d":
			directory = sys.argv[2]
			if sys.argv[3] == "-u":
				username = sys.argv[4]
		else:
			print("Usage: <command>.py -u <username> [-d <directory>]")
			exit()
	os.system("last -2 " + username + " > login.txt")	
	with open('login.txt') as logins:
		log = logins.readline()
		new_log = logins.readline()	
	parts = log.split()
	if len(parts) != 0:
		length_logged_in = parts[-1]
		length_logged_in = length_logged_in.strip('()')
		date_time = str(parts[3]) + ' ' + str(parts[4]) + ' ' + str(parts[5])
	else:
		parts = new_log.split()
		length_logged_in = -1
		date_time = str(parts[-4] + ' ' + str(parts[-3]) + ' ' + str(parts[-2]))
	user_files = []
	# Going through the filesystem from given root directory or / as default
	for root, dirs, files in os.walk(directory):
		for f in files:
			#For each file in directory walk, compare owner to username given
			#If user created the file, add it to the list
			try:
				if pwd.getpwuid(os.stat(f).st_uid).pw_name == username:
					user_files.append(os.path.join(root, f))
			except:
				pass	
	#Get hash for all user created files and check VirusTotal for maliciousness
	hash_list = []
	vt_result_list = []
	for file in user_files:
		hash = get_hash(file)
		hash_list.append((file, hash))
		#result = VT_request(hash)
		#if result == 'positive':
		#	vt_result_list.append(file)
		
	create_output(username, directory, date_time, length_logged_in, hash_list, vt_result_list)
	

if __name__ == "__main__":
	main()
