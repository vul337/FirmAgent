from docker:dind

workdir /root
run apk add python3 py3-jinja2 py3-pip aws-cli
run pip install sonyflake-py pymongo
add fuzz_bins /root/fuzz_bins
add templates /root/templates
add entrypoint.sh /root/entrypoint.sh
add build_fuzz_img.py /root/build_fuzz_img.py
add fuzz_gh.sh /root/fuzz_gh.sh
entrypoint ["/root/entrypoint.sh"]
