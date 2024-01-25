Anonymize IPv(4|6) addresses infile while preserving country information.
This script uses MaxMind GeoLite2 database for country information.

primarly intended to be used in logrotate's 'prerotate'-section like

...
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
{
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    prerotate
        /usr/local/sbin/anonyme.py $1
    endscript
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
...

amused by the lameness of other "solutions" it let chatGPT write that ..

HA - . one day i really will read that book and learn to really code python x-D
