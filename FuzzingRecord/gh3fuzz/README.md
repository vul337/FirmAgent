# gh3fuzz

Fuzzing harness for AFL++ with Greenhouse in a deployable docker container.

Note that `gh3fuzz` is largely experimental code and is mainly provided as a reference for the paper.

## Requirements

(Tested on Ubuntu 20.04)

- python3.7 or higher
- jinja2
- docker 24.0.4 or higher

You also need
- binfmt-support
- qemu-user-static

Install in Ubuntu with:
`sudo apt-get install binfmt-support qemu-user-static`

## Instructions

1) Set up the machine for fuzzing:

```
sudo su
echo core > /proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```

2) Setup the fuzzing bins

```
cd fuzz_bins_src
make
cd ..
```

This creates a folder `fuzz_bins` in the parent in the parent directory. 

2) A fuzzing container for a given rehosted Greenhouse sample can be run via:

```
python3 build_fuzz_img.py -f <path-to-rehosted-greenhouse-image.tar.gz> 
docker run --privileged fuzzing_dude_img
```

3) AFL++ output is printed to stdout, while results can be found in the `/scratch/output` directory of the docker container. These can be copied out with `docker cp` and manually analyzed/examined accordingly. The fuzzing can be stopped by using `docker stop <container-name>`.

Note that the docker container environment is pretty stripped down to optimize our fuzzing and uses only a basic `sh` as an interactive terminal.

To insert specific seeds, before building modify the `fuzz_bins/seeds` directory by deleting the existing seed files (which are from our comparison experiment against EQUAFL) and copying in your own as per AFL documentation.
