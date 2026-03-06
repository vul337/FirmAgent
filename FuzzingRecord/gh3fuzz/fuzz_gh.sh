#!/bin/sh

aws --endpoint-url "$GH_TAR_ENDPOINT" s3 cp "$GH_TAR" /root/gh.tar.gz
python3 build_fuzz_img.py -f /root/gh.tar.gz -n fuzz
docker run --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt seccomp=unconfined -v /scratch:/scratch -i --name fuzz fuzz &

mkdir /root/seen
mkdir /root/meta
function idgen () {
	python3 <<EOF
import sonyflake
sf = sonyflake.SonyFlake(machine_id=lambda: int('$SAMPLE') & 0xffff)
print(sf.next_id())
EOF
}
function put_meta () {
	python3 <<EOF
import pymongo, yaml
a = pymongo.MongoClient("$MONGO_URL")
b = a.get_database("$MONGO_DATABASE").get_collection("haccs_pipeline")["$MONGO_SUBCOLLECTION"]
c = yaml.safe_load(open("$2", "r"))
b.replace_one({"_id": "$1"}, c, upsert=True)
EOF
}
function put_meta_tmin () {
	python3 <<EOF
import pymongo, yaml
a = pymongo.MongoClient("$MONGO_URL")
b = a.get_database("$MONGO_DATABASE").get_collection("haccs_pipeline")["$MONGO_SUBCOLLECTION_TMIN"]
c = yaml.safe_load(open("$2", "r"))
b.replace_one({"_id": "$1"}, c, upsert=True)
EOF
}
function sync_crashes () {
	for crash_base in $(ls /scratch/output/default/crashes 2>/dev/null | grep -v README); do
		crash_full="/scratch/output/default/crashes/$crash_base"
		if [ ! -L "/root/seen/$crash_base" ]; then
			ln -s "$crash_full" "/root/seen/$crash_base"
			ident=$(idgen)
			echo "****** New crash! ******"
			echo "Assigning $ident to $crash_base"
			aws --endpoint-url "$CRASH_ENDPOINT" s3 cp "$crash_full" "s3://$CRASH_BUCKET/$CRASH_PREFIX$ident$CRASH_SUFFIX"
			cat >/root/meta/$ident.yaml <<EOF
sample: "$SAMPLE"
filename: "$crash_base"
EOF
			put_meta $ident /root/meta/$ident.yaml
		fi
	done
}

function sync_tmin_crashes () {
	for crash_base in $(ls /scratch/output/tmin 2>/dev/null | grep -v README); do
		crash_full="/scratch/output/tmin/$crash_base"
		ident=$(idgen)
		echo "****** Minified crash! ******"
		echo "Assigning $ident to $crash_base"
		aws --endpoint-url "$CRASH_ENDPOINT" s3 cp "$crash_full" "s3://$TMIN_BUCKET/$TMIN_PREFIX$ident$TMIN_SUFFIX"
		cat >/root/meta/$ident.yaml <<EOF
sample: "$SAMPLE"
filename: "$crash_base"
EOF
		put_meta_tmin $ident /root/meta/$ident.yaml
	done
}

function monitor () {
	while ! [ -e "/tmp/timed_out" ]; do
		sleep 30
		sync_crashes
	done
	touch "/tmp/finished"
}
monitor &

sleep "$FUZZ_TIMEOUT"
touch /tmp/timed_out
while ! [ -e "/tmp/finished" ]; do sleep 10; done
docker kill fuzz
docker run --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt seccomp=unconfined -v /scratch:/scratch -i --name tmin fuzz /minify.sh
sync_tmin_crashes
