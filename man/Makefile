all: himmelblau.conf
	rm -rf ./data && ./aad-tool-help2man && ./combine.py
	pandoc -s -t man -o man8/pam_himmelblau.8 ./pam_himmelblau.md

# Generate himmelblau.conf(5) man page from XML parameter definitions
himmelblau.conf:
	python3 ../scripts/gen_param_code.py --gen-man --man-output man5/himmelblau.conf.5
