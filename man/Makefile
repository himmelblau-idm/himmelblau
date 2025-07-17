all:
	rm -rf ./data && ./aad-tool-help2man && ./combine.py
	pandoc -s -t man -o man8/pam_himmelblau.8 ./pam_himmelblau.md
