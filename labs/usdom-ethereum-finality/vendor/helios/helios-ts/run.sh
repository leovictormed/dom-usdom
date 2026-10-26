#!/bin/sh
set -e
npm run build
simple-http-server
