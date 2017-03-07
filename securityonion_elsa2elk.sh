#!/bin/bash
# Convert Security Onion ELSA to ELK

# Check for prerequisites
if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run using sudo!"
	exit 1
fi

for FILE in /etc/nsm/securityonion.conf /etc/nsm/sensortab; do
	if [ ! -f $FILE ]; then
		echo "$FILE not found!  Exiting!"
		exit 1
	fi
done

if ! grep -i "ELSA=YES" /etc/nsm/securityonion.conf > /dev/null 2>&1 ; then
	echo "ELSA is not enabled!  Exiting!"
	exit 1
fi

if [ -f /root/.ssh/securityonion_ssh.conf ]; then
	echo "This script can only be executed on boxes running in Evaluation Mode.  Exiting!"
	exit 1
fi

SENSOR=`grep -v "^#" /etc/nsm/sensortab | tail -1 | awk '{print $1}'`
if ! grep 'PCAP_OPTIONS="-c"' /etc/nsm/$SENSOR/sensor.conf > /dev/null 2>&1 ; then
	echo "This script can only be executed on boxes running in Evaluation Mode.  Exiting!"
	exit 1
fi

clear
cat << EOF 
This QUICK and DIRTY script is designed to allow you to quickly and easily experiment
with ELK (Elasticsearch, Logstash, and Kibana) on Security Onion.

This script assumes that you're running the latest Security Onion 14.04.5.2 ISO image
and that you've already run through Setup, choosing Evaluation Mode to enable ELSA.

This script will do the following:
- install OpenJDK 7 from Ubuntu repos (we'll move to OpenJDK 8 when we move to Ubuntu 16.04)
- download ELK packages from Elastic (in the future, we'll build our own packages)
- install and configure ELK
- disable ELSA
- configure syslog-ng to send logs to ELK
- configure Apache as a reverse proxy for Kibana and authenticate users against Sguil database
- replay sample pcaps to provide data for testing

TODO
- Import Kibana index patterns
- Import Kibana visualizations
- Import Kibana dashboards
- Add code to CapMe to query Elasticsearch
- Determine method of pivoting from Kibana to CapMe (most likely Bro CID for now)
- Configure Squert to query ES directly
- Store Elasticsearch data at /nsm

HARDWARE REQUIREMENTS
ELK requires more hardware than ELSA, so for a test VM, you'll probably want at least 4GB of RAM.

THANKS
Special thanks to Justin Henderson for his Logstash configs and installation guide!
https://github.com/SMAPPER/Logstash-Configs

WARNINGS AND DISCLAIMERS
This script is PRE-ALPHA, BLEEDING EDGE, and totally UNSUPPORTED!
If this script breaks your system, you get to keep both pieces!
Use of this script may result in nausea, vomiting, or a burning sensation.
Do NOT run this on a system that you care about!
Do NOT run this on a system that has data that you care about!
This script should only be run on a TEST box with TEST data!
This script is only designed for standalone boxes and does NOT support distributed deployments.
 
Once you've read all of the WARNINGS AND DISCLAIMERS above, please type AGREE to proceed:
EOF
read INPUT
if [ "$INPUT" != "AGREE" ] ; then exit 0; fi

# Make a directory to store downloads
DIR="/tmp/elk"
mkdir $DIR
cd $DIR

# Define a banner to separate sections
banner="========================================================================="

header() {
	echo
	printf '%s\n' "$banner" "$*" "$banner"
}

header "Installing OpenJDK"
apt-get update > /dev/null
apt-get install openjdk-7-jre-headless -y

header "Downloading ELK packages"
wget https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/deb/elasticsearch/2.4.4/elasticsearch-2.4.4.deb
wget https://download.elastic.co/logstash/logstash/packages/debian/logstash-2.4.1_all.deb
wget https://download.elastic.co/kibana/kibana/kibana-4.6.4-amd64.deb
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | apt-key add -

header "Installing ELK packages"
dpkg -i /tmp/elk/elasticsearch-*.deb
dpkg -i /tmp/elk/logstash-*_all.deb
dpkg -i /tmp/elk/kibana-*-amd64.deb

header "Downloading GeoIP data"
mkdir /usr/local/share/GeoIP
cd /usr/local/share/GeoIP
rm Geo*.dat
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip *.gz
cd $DIR

header "Installing ELK plugins"
apt-get install python-pip -y
pip install elasticsearch-curator
/usr/share/elasticsearch/bin/plugin install lmenezes/elasticsearch-kopf
/opt/logstash/bin/logstash-plugin install logstash-filter-translate
/opt/logstash/bin/logstash-plugin install logstash-filter-tld
/opt/logstash/bin/logstash-plugin install logstash-filter-elasticsearch
/opt/logstash/bin/logstash-plugin install logstash-filter-rest
/opt/kibana/bin/kibana plugin --install elastic/sense
/opt/kibana/bin/kibana plugin --install prelert_swimlane_vis -u https://github.com/prelert/kibana-swimlane-vis/archive/v0.1.0.tar.gz
git clone https://github.com/oxalide/kibana_metric_vis_colors.git
apt-get install zip -y
zip -r kibana_metric_vis_colors kibana_metric_vis_colors
/opt/kibana/bin/kibana plugin --install metric-vis-colors -u file://$DIR/kibana_metric_vis_colors.zip
/opt/kibana/bin/kibana plugin -i kibana-slider-plugin -u https://github.com/raystorm-place/kibana-slider-plugin/releases/download/v0.0.2/kibana-slider-plugin-v0.0.2.tar.gz
/opt/kibana/bin/kibana plugin --install elastic/timelion
/opt/kibana/bin/kibana plugin -i kibana-html-plugin -u https://github.com/raystorm-place/kibana-html-plugin/releases/download/v0.0.3/kibana-html-plugin-v0.0.3.tar.gz

header "Configuring ElasticSearch"
FILE="/etc/elasticsearch/elasticsearch.yml"
echo "network.host: 127.0.0.1" >> $FILE
echo "cluster.name: securityonion" >> $FILE
echo "index.number_of_replicas: 0" >> $FILE

header "Installing logstash config files"
apt-get install git -y
git clone https://github.com/dougburks/Logstash-Configs.git
cp -rf Logstash-Configs/configfiles/*.conf /etc/logstash/conf.d/
cp -rf Logstash-Configs/dictionaries /lib/
cp -rf Logstash-Configs/grok-patterns /lib/

header "Configuring Apache to reverse proxy Kibana and authenticate against Sguil database"
cp Logstash-Configs/proxy/securityonion.conf /etc/apache2/sites-available/
cp Logstash-Configs/proxy/so-kibana-auth /usr/local/bin/
apt-get install libapache2-mod-authnz-external -y

header "Enabling ELK"
update-rc.d elasticsearch defaults
update-rc.d logstash defaults
update-rc.d kibana defaults

header "Starting ELK"
service elasticsearch start
service logstash start
service kibana start

header "Disabling ELSA"
FILE="/etc/nsm/securityonion.conf"
sed -i 's/ELSA=YES/ELSA=NO/' $FILE
service sphinxsearch stop
echo "manual" > /etc/init/sphinxsearch.conf.override
a2dissite elsa
service apache2 restart

header "Reconfiguring syslog-ng to send logs to ELK"
FILE="/etc/syslog-ng/syslog-ng.conf"
cp $FILE $FILE.elsa
sed -i '/^destination d_elsa/a destination d_elk { tcp("127.0.0.1" port(6050) template("$(format-json --scope selected_macros --scope nv_pairs --exclude DATE --key ISODATE)\n")); };' $FILE
sed -i 's/log { destination(d_elsa); };/log { destination(d_elk); };/' $FILE
sed -i '/rewrite(r_host);/d' $FILE
sed -i '/rewrite(r_cisco_program);/d' $FILE
sed -i '/rewrite(r_snare);/d' $FILE
sed -i '/rewrite(r_from_pipes);/d' $FILE
sed -i '/rewrite(r_pipes);/d' $FILE
sed -i '/parser(p_db);/d' $FILE
sed -i '/rewrite(r_extracted_host);/d' $FILE
service syslog-ng restart

if [ -f /etc/nsm/sensortab ]; then
	NUM_INTERFACES=`grep -v "^#" /etc/nsm/sensortab | wc -l`
	if [ $NUM_INTERFACES -gt 0 ]; then
		header "Replaying pcaps in /opt/samples/ to create logs"
		INTERFACE=`grep -v "^#" /etc/nsm/sensortab | head -1 | awk '{print $4}'`
		for i in /opt/samples/*.pcap /opt/samples/markofu/*.pcap /opt/samples/mta/*.pcap; do
		echo -n "." 
		tcpreplay -i $INTERFACE -M10 $i >/dev/null 2>&1
		done
	fi
fi

header "All done!"
cat << EOF

After a minute or two, you should be able to access Kibana via the following URL:
https://localhost/app/kibana

Kibana should then prompt for an index pattern.  Click the Time-field name drop-down box,
select @timestamp, and click the Create button.

Click the Discover tab and start slicing and dicing your logs!

You should see Bro logs, syslog, and Snort alerts.  Most of the parsers are just for Bro logs right now.

For additional (optional) configuration, please see:
https://github.com/dougburks/Logstash-Configs/blob/master/securityonion_elk_install.txt
EOF
