#!/bin/bash

export VANILLA_IMAGE="public.ecr.aws/lts/ubuntu:focal"
export HARDENED_IMAGE="canonical/ubuntu-pro-stig-20.04:latest"

echo "BUILD: build the hardened ubuntu image"
docker build https://repo1.dso.mil/dsop/canonical/ubuntu/ubuntu-pro-cis-stig-20.04.git\#development \
  --tag $HARDENED_IMAGE

echo "CREATE: create target containers for testing"
docker run -itd --rm --name vanilla-ubuntu $VANILLA_IMAGE
docker run -itd --rm --name hardened-ubuntu $HARDENED_IMAGE

docker ps -f name=-ubuntu

echo "TEST: run InSpec against the vanilla container"
inspec exec . --input-file=container.inputs.yml -t docker://vanilla-ubuntu --reporter json:vanilla.json cli

echo "TEST: run InSpec against the hardened container"
inspec exec . --input-file=container.inputs.yml -t docker://hardened-ubuntu --reporter json:hardened.json cli

echo "TEST: summary of vanilla results"
saf view summary -i vanilla.json

echo "TEST: summary of hardened results"
saf view summary -i hardened.json

echo "VALIDATE: validating vanilla results passed thresholds. . ."
saf validate:threshold -i vanilla.json -F container.vanilla.threshold.yml

echo "Generate scan report for vanilla"
saf generate:threshold -i vanilla.json -c -o vanilla-report.md
sed -i '' '1s/^/```yaml\'$'\n/' vanilla-report.md 
echo '```' | tee -a vanilla-report.md 

echo "VALIDATE: validating hardened results passed thresholds. . ."
saf validate:threshold -i hardened.json -F container.hardened.threshold.yml

echo "Generate scan report for hardened scan"
saf generate:threshold -i hardened.json -c -o hardened-report.md
sed -i '' '1s/^/```yaml\'$'\n/' hardened-report.md 
echo '```' | tee -a hardened-report.md
