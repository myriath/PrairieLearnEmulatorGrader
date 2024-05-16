#!/bin/bash
VERS=1.0

mkdir build
(cd tiva_qemu && git pull)
git pull

(cd build && ../tiva_qemu/configure && make)

sudo docker image build . -t prairielearn/emu_grader:v$VERS

printf "\nCurrent image tag: prairielearn/emu_grader:v$VERS\n"
