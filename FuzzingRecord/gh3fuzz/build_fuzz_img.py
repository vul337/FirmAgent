import os
import re
import glob
import json
import tempfile
import subprocess

import jinja2
import sys

env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
    trim_blocks=True)
fuzz_template = env.get_template("fuzz.sh.j2")
postauth_fuzz_template = env.get_template("postauth_fuzz.sh.j2")
finish_template = env.get_template("finish.sh.j2")
minify_template = env.get_template("minify.sh.j2")

class FuzzerBuilder:
    def __init__(self, fw_path, img_name):
        self.fw_path = os.path.abspath(fw_path)
        self.img_name = img_name

        self.workdir = None
        self.img_dir = None
        self.config = None
        self._arch = None
        self._cmd = None

    def _get_info(self):
        """
        extract the architecture
        TODO: do it properly
        """
        dockerfile = os.path.join(self.img_dir, "Dockerfile")
        assert os.path.exists(dockerfile)
        with open(dockerfile, 'r') as f:
            for line in f:
                if 'CMD' in line:
                    # extract arch
                    res = re.search("qemu-(.*)-static", line)
                    arch = res.group(1)
                    self._arch = arch

                    # extract command
                    cmd_argv = json.loads(line.split(maxsplit=1)[1])
                    assert '--' in cmd_argv
                    cmd_argv = cmd_argv[cmd_argv.index('--')+1:]
                    self._cmd = ' '.join(cmd_argv)
                    return
            else:
                raise RuntimeError("????")

    def _extract_dict(self):
        bin_path = os.path.join(self.img_dir, "fs", os.path.relpath(self.config['targetpath'], "/"))
        assert os.path.exists(bin_path)
        strs = subprocess.getoutput(f"strings {bin_path}").splitlines()
        strs = [x for x in strs if "'" not in x and '"' not in x] # avoid troubles
        strs = ["GET", "POST", "/", "HTTP"] + strs
        strs = list(set(strs))
        with open(os.path.join(self.img_dir, "dictionary"), "w") as f:
            for i, s in enumerate(strs):
                if any(x in list(s.encode()) for x in list(range(128, 256))+list(range(1, 32))):
                    continue
                f.write(f'str{i}="{s}"\n')

    def _assemble_fuzz_script(self):
        # generate commands for the background script
        bg_block = ""
        background = self.config['background']
        if type(background[0]) is not list:
            background = [background]
        for stuff in background:
            assert 1<= len(stuff) <= 2
            for x in stuff:
                if type(x) is str:
                    bg_block += x
                    bg_block += "\n"
                elif type(x) is int:
                    bg_block += f"/fuzz_bins/utils/sleep {x}\n"
                else:
                    raise

        # render the fuzzing script
        if 'seconds_to_up' in self.config:
            timeout = int(self.config['seconds_to_up'] + 10)
        else:
            timeout = 10
        content = fuzz_template.render(arch=self._arch, cmd=f'"{self._cmd}"', bg_block=bg_block, timeout=timeout)
        fpath = os.path.join(self.img_dir, "fuzz.sh")
        with open(fpath, "w") as f:
            f.write(content)
        os.chmod(fpath, 0o755)

        # render the postauth fuzzing script
        brand = self.config['brand']
        content = postauth_fuzz_template.render(arch=self._arch, cmd=f'"{self._cmd}"', bg_block=bg_block, brand=brand, timeout=timeout)
        fpath = os.path.join(self.img_dir, "postauth_fuzz.sh")
        with open(fpath, "w") as f:
            f.write(content)
        os.chmod(fpath, 0o755)

        # render the finish script
        content = finish_template.render()
        fpath = os.path.join(self.img_dir, "finish.sh")
        with open(fpath, "w") as f:
            f.write(content)
        os.chmod(fpath, 0o755)

        # render the minify script
        content = minify_template.render(cmd=f'"{self._cmd}"')
        fpath = os.path.join(self.img_dir, "minify.sh")
        with open(fpath, "w") as f:
            f.write(content)
        os.chmod(fpath, 0o755)

    def _assemble_dockerfile(self):
        with open(os.path.join(self.img_dir, "Dockerfile")) as f:
            lines = f.read().splitlines()
        with open(os.path.join(self.img_dir, "Dockerfile"), 'w') as f:
            for line in lines:
                if line.startswith("FROM"): # prologue
                    f.write("FROM scratch\n")
                elif line.startswith("ENTRYPOINT"): # skip
                    continue
                elif line.startswith("CMD"): # epilogue
                    f.write("COPY config.json /config.json\n")
                    f.write("COPY fuzz_bins /fuzz_bins\n")
                    f.write("COPY seeds /fuzz/seeds\n")
                    f.write("COPY dictionary /fuzz/dictionary\n")
                    f.write("COPY fuzz.sh /fuzz.sh\n")
                    f.write("COPY postauth_fuzz.sh /postauth_fuzz.sh\n")
                    f.write("COPY finish.sh /finish.sh\n")
                    f.write("COPY minify.sh /minify.sh\n")
                    f.write("COPY x86_64-linux-gnu /lib/x86_64-linux-gnu\n")
                    f.write("COPY ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2\n")
                    f.write("COPY libibresolver.so /libibresolver.so\n")
                    f.write(f'RUN ["/fuzz_bins/utils/cp", "/fuzz_bins/qemu/afl-qemu-trace-{self._arch}", "/usr/bin/afl-qemu-trace"]\n')
                    f.write("WORKDIR /scratch\n")
                    f.write("CMD /fuzz.sh\n")
                    continue
                else:
                    f.write(line+"\n")
        #with open(os.path.join(self.img_dir, "Dockerfile")) as f:
        #    print(f.read())

    def _build_docker(self):
        # copy seeds
        src_path = os.path.join(os.path.dirname(__file__), "fuzz_bins", "seeds")
        dst_path = os.path.join(self.img_dir, "seeds")
        os.system(f"cp -r {src_path} {dst_path}")
        
        # copy Lib
        src_path = os.path.join(os.path.dirname(__file__), "x86_64-linux-gnu")
        dst_path = os.path.join(self.img_dir, "x86_64-linux-gnu")
        os.system(f"cp -r {src_path} {dst_path}")
        
        src_path = os.path.join(os.path.dirname(__file__), "ld-linux-x86-64.so.2")
        dst_path = os.path.join(self.img_dir, "ld-linux-x86-64.so.2")
        os.system(f"cp  {src_path} {dst_path}")
        
        src_path = os.path.join(os.path.dirname(__file__), "libibresolver.so")
        dst_path = os.path.join(self.img_dir, "libibresolver.so")
        os.system(f"cp  {src_path} {dst_path}")
        
        # copy fuzz_bins
        src_path = os.path.join(os.path.dirname(__file__), "fuzz_bins")
        dst_path = os.path.join(self.img_dir, "fuzz_bins")
        os.system(f"cp -r {src_path} {dst_path}")
        
        path_parts = self.img_dir.split('/')
        self.img_name = path_parts[-2].lower()
        print(self.img_name)
        
        ret = subprocess.call(["docker", "build", "-t", self.img_name, "."], cwd=self.img_dir)
        assert ret == 0


    def build(self):
        self._get_info()
        self._extract_dict()
        self._assemble_fuzz_script()
        self._assemble_dockerfile()
        self._build_docker()

    def __enter__(self):
        self.workdir = tempfile.TemporaryDirectory(prefix="gh-")
        os.system(f"tar -xf {self.fw_path} -C {self.workdir.name}")
        tmp = glob.glob(os.path.join(self.workdir.name, "*", "*", "config.json"))
        assert len(tmp) == 1
        config_path = tmp[0]
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.img_dir = os.path.join(os.path.dirname(config_path), "minimal")
        with open(os.path.join(self.img_dir, 'config.json'), 'w') as f:
            config = self.config.copy()
            old_ip = self.config['targetip']
            config["targetip"] = "0.0.0.0"
            config["loginurl"] = config["loginurl"].replace(old_ip, "0.0.0.0")
            json.dump(config, f, indent=4)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.workdir.cleanup()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='generate a docker image for fuzzing from a firmware image',
                                     usage="%(prog)s -f <firmware_image> -n <container_name>")
    parser.add_argument('-f', '--firmware', type=str,
                        help="the path to the tarfile of the firmware", required=True)
    parser.add_argument('-n', '--name', type=str,
                        help="the name of the final container image", default="fuzzing_dude_img")
    parser.add_argument('-p', '--push', action='store_true',
                        help="push the resulting image", default=False)
    args = parser.parse_args()

    with FuzzerBuilder(args.firmware, args.name) as builder:
        builder.build()
        #import IPython; IPython.embed()

    if args.push:
        subprocess.run(['docker', 'push', args.name], check=True)
