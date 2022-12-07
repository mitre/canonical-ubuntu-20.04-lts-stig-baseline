#!/bin/bash

VANILLA_IMAGE=public.ecr.aws/lts/ubuntu:focal
HARDENED_IMAGE=canonical/ubuntu-pro-stig-20.04:latest

echo "BUILD: build the hardened ubuntu image"
docker build https://repo1.dso.mil/dsop/canonical/ubuntu/ubuntu-pro-cis-stig-20.04.git\#development \
  --tag $HARDENED_IMAGE

echo "CREATE: create target containers for testing"
docker run -dit --rm --name vanilla-ubuntu $VANILLA_IMAGE
docker run -dit --rm --name hardened-ubuntu $HARDENED_IMAGE\

docker ps -f name=-ubuntu

echo "TEST: run InSpec against the vanilla container"
inspec exec . --input-file=container.inputs.yml -t docker://vanilla-ubuntu --reporter json:vanilla.json progress-bar

echo "TEST: run InSpec against the hardened container"
inspec exec . --input-file=container.inputs.yml -t docker://hardened-ubuntu --reporter json:hardened.json progress-bar

echo "TEST: summary of vanilla results"
saf view summary -i vanilla.json

echo "TEST: summary of hardened results"
saf view summary -i hardened.json

echo "VALIDATE: validating vanilla results passed thresholds. . ."
saf validate:threshold -i vanilla.json -F vanilla.threshold.yml

echo "VALIDATE: validating hardened results passed thresholds. . ."
saf validate:threshold -i hardened.json -F hardened.threshold.yml