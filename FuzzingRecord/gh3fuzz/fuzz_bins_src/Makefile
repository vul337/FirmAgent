.PHONY: all gen_patch
all:
	# @echo 'building docker image haccs_fuzzing_dude...'
	# sleep 1
	# docker build -t haccs_fuzzing_dude .
	@echo 'run image haccs_fuzzing_dude to build the supporting binaries...'
	sleep 1
	docker run --rm -v `pwd`/../fuzz_bins:/AFLplusplus_out -it haccs_fuzzing_dude bash -c 'rm -rf /AFLplusplus_out/*; cp -a /AFLplusplus_release/* /AFLplusplus_out/; mkdir /AFLplusplus_out/qemu; cp /AFLplusplus/afl-qemu-trace* /AFLplusplus_out/qemu/; chown -R '$(shell id -u):$(shell id -g)' /AFLplusplus_out'
	cp -r seeds `pwd`/../fuzz_bins/seeds

gen_patch:
	@echo "building docker image haccs_fuzzing_dude"
	sleep 1
	docker build -f gen_patch.dockerfile -t haccs_fuzzing_dude .
	@echo "run image haccs_fuzzing_dude to generate patch"
	docker run --rm -it haccs_fuzzing_dude bash
