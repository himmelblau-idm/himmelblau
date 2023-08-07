all:
	if ! podman images | grep himmelblau | grep -q testing; then podman build -t himmelblau:testing .; fi

test:
	tar --exclude-vcs --exclude="target" --exclude="himmelblau.tar.gz" -zcvf himmelblau.tar.gz ../
	podman run --volume=../target/debug/deps:/root/build/target/debug/deps --volume=./:/root/tests --rm himmelblau:testing

exec: clean-exec
	podman run --volume=./:/root/tests --detach --name himmelblau_testing_exec himmelblau:testing --hang
	podman exec -ti himmelblau_testing_exec bash; podman kill himmelblau_testing_exec
	podman container rm himmelblau_testing_exec

clean-exec:
	podman container stop himmelblau_testing_exec >/dev/null 2>&1; echo
	podman container rm himmelblau_testing_exec >/dev/null 2>&1; echo

clean: clean-exec
	rm -rf himmelblau.tar.gz; echo
	podman image rm himmelblau:testing; echo
