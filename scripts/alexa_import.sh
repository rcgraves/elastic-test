#!/bin/bash
# Author: Justin Henderson
# Email: jhenderson@tekrefresh.com
# Last Update: 10/31/2016
#
# This script is intended to be ran as either a weekly or daily cron job.
# It will download the alexa top 1 million sites and unzip it for Logstash to retrieve.

cd /tmp && /usr/bin/wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip && /usr/bin/unzip -o top-1m.csv.zip -d /etc/logstash/data && rm /tmp/top-1m.csv.zip
