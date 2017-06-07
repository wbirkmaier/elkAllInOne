#!/bin/bash
#Names must be in hosts or dns files
mkdir -p /etc/pki/tls/certs
scp elk1-01.prod.com:/etc/pki/tls/certs/logstash-forwarder.crt /etc/pki/tls/certs/.
scp elk1-01.prod.com:/root/filebeat-1.3.1-x86_64.rpm .
#rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
#cat <<'EOF' >> /etc/yum.repos.d/elastic-beats.repo
#[beats]
#name=Elastic Beats Repository
#baseurl=https://packages.elastic.co/beats/yum/el/$basearch
#enabled=1
#gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
#gpgcheck=1
#EOF

yum -y install filebeat-1.3.1-x86_64.rpm --nogpgcheck

cat <<'EOF' > /etc/filebeat/filebeat.yml
filebeat:
  prospectors:
    -
      paths:
        #- /var/log/*.log
        #- /var/log/httpd/*/access_log.*
        - /var/log/*
      input_type: log
      exclude_files: [".gz$"]
      #document_type: xenserver
      #document_type: apache
      document_type: syslog
    -
      paths:
        - /home/user/log/*Message.log
      input_type: log
      exclude_files: [".gz$"]
      document_type: jbosslog
    -
      paths:
        - /home/user/log/*JBoss.log
      input_type: log
      exclude_files: [".gz$"]
      document_type: jbosslog
    -
      paths:
        - /home/user/log/jboss*.out
      input_type: log
      exclude_files: [".gz$"]
      document_type: jbossout
  registry_file: /var/lib/filebeat/registry
output:
  logstash:
    hosts: ["elk1-01.prod.com:5044"]
    bulk_max_size: 1024
    tls:
      certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
shipper:
logging:
  files:
    rotateeverybytes: 10485760 # = 10MB
    # Number of rotated log files to keep. Oldest files will be deleted first.
    keepfiles: 2
EOF

#CentOS 6
chkconfig filebeat on
service filebeat start

#CentOS 7
#systemctl start filebeat
#systemctl enable filebeat

echo "Test with curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty' on elk server to see data"
