#!/bin/bash
#Names must be in hosts or dns files
#mkdir -p /etc/pki/tls/certs
scp elk1-03.prod.com:/etc/pki/tls/certs/logstash-forwarder.crt /etc/pki/tls/certs/logstash5-forwarder.crt
scp elk1-03.prod.com:/root/filebeat-5.4.0-x86_64.rpm .
#rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
#cat <<'EOF' >> /etc/yum.repos.d/elastic-beats.repo
#[beats]
#name=Elastic Beats Repository
#baseurl=https://packages.elastic.co/beats/yum/el/$basearch
#enabled=1
#gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
#gpgcheck=1
#EOF

yum -y install filebeat-5.4.0-x86_64.rpm --nogpgcheck

cat <<'EOF' > /etc/filebeat/filebeat.yml
filebeat.modules:
- module: apache2
  # Access logs
  access:
    enabled: true
filebeat.prospectors:
- input_type: log
  document_type: apache
  paths:
    #- /var/log/*.log
    #- /var/log/httpd/*/access_log.*
    - /var/log/httpd/mysite/access_log.*
  exclude_files: [".gz$"]
output.logstash:
  hosts: ["elk1-03.prod.com:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/logstash5-forwarder.crt"]
logging.to_files: true
logging.files:
  rotateeverybytes: 10485760 # = 10MB
  keepfiles: 2
EOF



/usr/share/filebeat/bin/filebeat -configtest -e

#CentOS 6
chkconfig filebeat on
service filebeat start

#CentOS 7
#systemctl start filebeat
#systemctl enable filebeat

echo "Test with curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty' on elk server to see data"
