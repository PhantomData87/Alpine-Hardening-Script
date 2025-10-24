#!/bin/bash

git add .
comment="\"$@\""
git commit -m "$comment"
git push origin master
