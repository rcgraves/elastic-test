#!/bin/bash
cd /tmp
/usr/bin/wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
/usr/bin/unzip -o top-1m.csv.zip -d /etc/logstash/data
rm /tmp/top-1m.csv.zip
curl -XPOST 'http://es01.test.int:9200/_aliases' -d '
{
    "actions" : [
        { "add" : { "index" : "logstash-alexa-'`date -u +%Y.%m.%d`'", "alias" : "alexa" } },
        { "remove" : { "index" : "logstash-alexa-'`date -u +%Y.%m.%d -d "1 day ago"`'", "alias" : "alexa" } },
        { "remove" : { "index" : "logstash-alexa-'`date -u +%Y.%m.%d -d "2 day ago"`'", "alias" : "alexa" } },
        { "remove" : { "index" : "logstash-alexa-'`date -u +%Y.%m.%d -d "3 day ago"`'", "alias" : "alexa" } }
    ]
}'
