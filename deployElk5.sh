#!/bin/bash
#Names must be in DNS or HOSTS file of this system
echo -e "\e[32mDisabling Firewall...\e[39m"
systemctl stop firewalld
systemctl disable firewalld

echo -e "\e32mDisabling IPV6...\e[39m"
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

echo -e "\e[32mDisabling selinux...\e[39m"
cp /etc/selinux/config /etc/selinux/config.bak
sed '/^SELINUX/ s/permissive/disabled/' /etc/selinux/config.bak > /etc/selinux/config
yum install -y wget

echo -e "\e[32mInstalling Java...\e[39m"
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/jdk-8u131-linux-x64.rpm"

sudo yum -y localinstall jdk-8u131-linux-x64.rpm

echo -e "\e[32mInstall Repositories...\e[39m"

sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

cat <<'EOF' >> /etc/yum.repos.d/elasticsearch.repo
[elasticsearch-5.x]
name=Elasticsearch repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

cat <<'EOF' >> /etc/yum.repos.d/kibana.repo
[kibana-5.x]
name=Kibana repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

cat <<'EOF' >> /etc/yum.repos.d/logstash.repo
[logstash-5.x]
name=Elastic repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

cat <<'EOF' >> /etc/yum.repos.d/nginx.repo
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/rhel/7/$basearch/
gpgcheck=1
enabled=1
EOF

yum -y install epel-release

yum clean all

echo -e "\e[32mInstall Elasticsearch...\e[39m"
yum -y install elasticsearch


cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.back
sed 's/#network.host: 192.168.0.1/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml.back > /etc/elasticsearch/elasticsearch.yml

echo -e "\e[32mStarting Elasticsearch...\e[39m"
systemctl start elasticsearch
systemctl enable elasticsearch

echo -e "\e[32mInstalling Kibana...\e[39m"
yum -y install kibana

cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.bak
sed 's/#server.host: "localhost"/server.host: "localhost"/g' /etc/kibana/kibana.yml.bak > /etc/kibana/kibana.yml

echo -e "\e[32mStarting Kibana...\e[39m"
systemctl start kibana
chkconfig kibana on

echo -e "\e[32mInstall User Agent and Geoip location for apache in elasticsearch...\e[39m"
/usr/share/elasticsearch/bin/elasticsearch-plugin install ingest-user-agent
/usr/share/elasticsearch/bin/elasticsearch-plugin install ingest-geoip
systemctl restart elasticsearch

echo -e "\e[32mInstalling nginx...\e[39m"
yum -y install httpd-tools
#yum --showduplicates list nginx
yum -y --nogpgcheck install nginx-1:1.12.0-1.el7.ngx.x86_64

#Encrypt password so we can pass through here
echo -e "\e[32mInstalling htpasswd file for admin user...\e[39m"
htpasswd -c /etc/nginx/htpasswd.users admin

#This could be done cleaner at a later point
cat <<'EOF' > /etc/nginx/nginx.conf
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       80 default_server;
        listen       [::]:80 default_server;
        server_name  _;
        root         /usr/share/nginx/html;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;
    }

# Settings for a TLS enabled server.
#
#    server {
#        listen       443 ssl http2 default_server;
#        listen       [::]:443 ssl http2 default_server;
#        server_name  _;
#        root         /usr/share/nginx/html;
#
#        ssl_certificate "/etc/pki/nginx/server.crt";
#        ssl_certificate_key "/etc/pki/nginx/private/server.key";
#        ssl_session_cache shared:SSL:1m;
#        ssl_session_timeout  10m;
#        ssl_ciphers HIGH:!aNULL:!MD5;
#        ssl_prefer_server_ciphers on;
#
#        # Load configuration files for the default server block.
#        include /etc/nginx/default.d/*.conf;
#
#        location / {
#        }
#
#        error_page 404 /404.html;
#            location = /40x.html {
#        }
#
#        error_page 500 502 503 504 /50x.html;
#            location = /50x.html {
#        }
#    }

}
EOF

#Should fix this to have dynamic server_name field
cat <<'EOF' >> /etc/nginx/conf.d/kibana.conf
server {
    listen 80;

    server_name tsys-elk1-01.sv5.us.genprod;

    return 301 https://$host$request_uri;

}

server {
    listen       443 ssl http2 default_server;

    server_name tsys-elk1-01.sv5.us.genprod;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    ssl_certificate "/etc/pki/tls/certs/logstash-forwarder.crt";
    ssl_certificate_key "/etc/pki/tls/private/logstash-forwarder.key";
    ssl_session_cache shared:SSL:1m;
    ssl_session_timeout  10m;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF

echo -e "\e[32mGenerating Public Private Key Pair in /etc/pki/tls...\e[39m"
sudo openssl req -subj '/CN=tsys-elk1-01.sv5.us.genprod/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt

echo -e "\e[32mStarting nginx...\e[39m"
systemctl start nginx
systemctl enable nginx

echo -e "\e[32mInstalling Logstash...\e[39m"
yum -y install logstash

#Should switch to multiline code, as the filter is depricated
/usr/share/logstash/bin/logstash-plugin install logstash-filter-multiline

cat <<'EOF' >> /etc/logstash/conf.d/02-beats-input.conf
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/05-syslogd-input.conf
input {
   tcp {
     port => 5000
     type => "syslogd"
   }
   udp {
     port => 5000
     type => "syslogd"
   }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/10-syslog-filter.conf
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/11-syslogd-filter.conf
filter {
  if [type] == "syslogd" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/30-elasticsearch-output.conf
output {

  if [type] == "syslogd" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "syslogd-%{+YYYY.MM.dd}"
    }
  }

  else {
    elasticsearch {
      hosts => ["localhost:9200"]
      sniffing => true
      manage_template => false
      index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
      document_type => "%{[@metadata][type]}"
    }
  }
}
EOF

#Outbound uses this log format:
#Sample 10.12.5.14 - - [22/Mar/2017:14:59:56 +0000] "POST /site/a/4/MessageServerRegistry/messageServerState HTTP/1.1" 200 60 "-" "Apache-HttpClient/4.1.2 (java 1.5)" 817 621 **0/41988**
cat <<'EOF' >> /etc/logstash/conf.d/12-apache-filter.conf
filter {
  if [type] == "apache" {
    grok {
	match => [ "message", "%{IP:client_ip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:apache_timestamp}\] \"%{WORD:method} /%{NOTSPACE:request_page} HTTP/%{NUMBER:http_version}\" %{NUMBER:server_response} %{NUMBER:bytes} \"%{GREEDYDATA:referer}\" \"%{GREEDYDATA:user_agent}\" %{NUMBER:received} %{NUMBER:sent} \**%{NUMBER:duration_seconds}/%{NUMBER:duration_micro}\*\*" ]
    }
    date {
  match => [ "apache_timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
   locale => en
    }
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/13-jboss-out-filter.conf
filter {
  if [type] == "jbossout" {
    grok {
	match => [ "message", "%{TIME:time} %{LOGLEVEL:loglevel}  \[%{DATA:class}\] %{GREEDYDATA:messageout}" ]
    }
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/14-jboss-log-filter.conf
filter {
  if [type] == "jbosslog" {
    grok {
  match => ["message", "(?m)%{DATE:date} %{TIME:time} %{DATA:loglevel} \[%{DATA:class}\] %{GREEDYDATA:messageout}" ]
    }

    multiline {
      pattern => "%{DATE:date}"
      what => "previous"
      negate=> true
    }
  }

  date {
    match => [ "timestamp" , "yyyy-MM-dd HH:mm:ss.SSS" ]
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/15-xenserver-filter.conf
filter {
  if [type] == "xenserver" {
    grok {
	match => [ "message", "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" ]
    }
  }
}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/16-tsys-trace.conf
filter {
  if [type] == "tsystrace" {
    grok {
      match => ["message", "%{YEAR:year}.%{MONTHNUM:month}.%{MONTHDAY:day} %{TIME:time} %{WORD:loglevel} \[%{DATA:Customer}\] %{JAVACLASS} %{GREEDYDATA:messageout}" ]
    }
      multiline {
      pattern => "%{YEAR:year}.%{MONTHNUM:month}.%{MONTHDAY:day}"
      what => "previous"
      negate => true
    }
  }

mutate {
    add_field => { "wiltime" => "%{year} %{month} %{day} %{time}" }
  }

date {
  match => [ "wiltime", "yyyy MM dd HH:mm:ss.SSS" ]
}

}
EOF

cat <<'EOF' >> /etc/logstash/conf.d/17-clayeth-filter.conf
filter {
  if [type] == "clayeth" {
    grok {
	match => [ "message", "%{HOUR}:%{MINUTE}:%{SECOND}%{DATA:UUID}ETH: GPU0 %{BASE10NUM:GPU0Mh} Mh/s, GPU1 %{BASE10NUM:GPU1Mh} Mh/s, GPU2 %{BASE10NUM:GPU2Mh} Mh/s, GPU3 %{BASE10NUM:GPU3Mh} Mh/s, GPU4 %{BASE10NUM:GPU4Mh} Mh/s, GPU5 %{BASE10NUM:GPU5Mh}" ]
	match => [ "message", "%{HOUR}:%{MINUTE}:%{SECOND}%{DATA:UUID}ETH - Total Speed: %{BASE10NUM:TOTALSPEED} Mh/s, Total Shares: %{BASE10NUM:TOTALSHARES}, Rejected: %{BASE10NUM:REJECTEDSHARES}, Time: %{GREEDYDATA:UPTIME}" ]
	match => [ "message", "%{HOUR}:%{MINUTE}:%{SECOND}%{DATA:UUID}ETH: %{DATESTAMP} - SHARE FOUND - \(GPU %{NUMBER:SHAREFOUND}\)" ]
    }
  }
}
EOF

#echo -e "\e[32mChecking Logstash Configuration...\e[39m"
#service logstash configtest

echo -e "\e[32mStarting Logstash...\e[39m"
systemctl restart logstash
chkconfig logstash on

#echo -e "\e[32mLoading Kibana Dashboards...\e[39m"

#cd
#curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
#yum -y install unzip
#unzip beats-dashboards-*.zip
#cd beats-dashboards-*
#./load.sh


#Should pull down a local copy to archive
#curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
cd

cat <<'EOF' >> filebeat-index-template.json
{
  "mappings": {
    "_default_": {
      "_all": {
        "enabled": true,
        "norms": {
          "enabled": false
        }
      },
      "dynamic_templates": [
        {
          "template1": {
            "mapping": {
              "doc_values": true,
              "ignore_above": 1024,
              "index": "not_analyzed",
              "type": "{dynamic_type}"
            },
            "match": "*"
          }
        }
      ],
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "message": {
          "type": "string",
          "index": "analyzed"
        },
        "offset": {
          "type": "long",
          "doc_values": "true"
        },
        "duration_micro": {
          "type": "long",
          "doc_values": "true"
        },
        "duration_seconds": {
          "type": "long",
          "doc_values": "true"
        },
        "bytes": {
          "type": "long",
          "doc_values": "true"
        },
        "received": {
          "type": "long",
          "doc_values": "true"
        },
        "sent": {
          "type": "long",
          "doc_values": "true"
        },
        "geoip"  : {
          "type" : "object",
          "dynamic": true,
          "properties" : {
            "location" : { "type" : "geo_point" }
          }
        }
      }
    }
  },
  "settings": {
    "index.refresh_interval": "5s"
  },
  "template": "filebeat-*"
}
EOF

echo -e "\e[32mInstall Curator...\e[39m"
yum install -y python-pip
pip install elasticsearch-curator

#Alternative for curator https://packages.elastic.co/curator/4/centos/7/Packages/elasticsearch-curator-4.2.6-1.x86_64.rpm

mkdir /etc/curator

cat <<'EOF' >> /etc/curator/delete_indices.yml
---
# THIS IS RUN DAILY IN SYSTEM WIDE CRONS
# curator --config CONFIG.YML [--dry-run] ACTION_FILE.YML
# curator_cli show_indices will show you the indices
# Remember, leave a key empty if there is no value.  None will be a string,
# not a Python "NoneType"
#
# Also remember that all examples have 'disable_action' set to True.  If you
# want to use this action as a template, be sure to set this to False after
# copying it.
actions:
  1:
    action: delete_indices
    description: >-
      Delete indices older than 30 days (based on index name), for filebeat- and syslog-
      prefixed indices. Ignore the error if the filter does not result in an
      actionable list of indices (ignore_empty_list) and exit cleanly.
    options:
      ignore_empty_list: True
      timeout_override:
      continue_if_exception: False
      disable_action: False
    filters:
    #- filtertype: pattern
      #kind: prefix
      #value: filebeat-
      #exclude:
    - filtertype: pattern
      kind: regex
      value: '^(filebeat-|syslogd-).*$'
      exclude:
    - filtertype: age
      source: name
      #source: creation_date
      direction: older
      timestring: '%Y.%m.%d'
      unit: days
      #unit: hours
      unit_count: 30
      exclude:
EOF

cat <<'EOF' >> /etc/curator/config.yml
---
# curator [--config CONFIG.YML] [--dry-run] ACTION_FILE.YML
# Remember, leave a key empty if there is no value.  None will be a string,
# not a Python "NoneType"
client:
  hosts:
    - 127.0.0.1
  port: 9200
  url_prefix:
  use_ssl: False
  certificate:
  client_cert:
  client_key:
  ssl_no_validate: False
  http_auth:
  timeout: 30
  master_only: False

logging:
  loglevel: INFO
  logfile:
  logformat: default
  blacklist: ['elasticsearch', 'urllib3']
EOF

echo -e "\e[32mInstalling Curator in cron.daily...\e[39m"

cat <<'EOF' >> /etc/cron.daily/curator
#!/bin/sh

curator --config /etc/curator/config.yml /etc/curator/delete_indices.yml

EXITVALUE=$?
if [ $EXITVALUE != 0 ]; then
    /usr/bin/logger -t curator "ALERT exited abnormally with [$EXITVALUE]"
fi
exit 0
EOF

chmod a+x /etc/cron.daily/curator

echo -e "\e[32mLoad filebeat-index-template.json into Elasticsearch...\e[39m"
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json

echo -e "\e[32mDownloading Filebeats...\e[39m"
cd
#wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-1.3.1-x86_64.rpm
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-5.4.0-x86_64.rpm
