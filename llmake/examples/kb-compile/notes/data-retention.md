data retention

logs: 30 days hot, 1 year cold (s3 glacier). pii in logs is a bug - scrub at
source. customer data deleted within 30 days of account closure. backups nightly,
kept 35 days. analytics events anonymized after 90 days. legal hold overrides
all of this - if legal says keep, keep.
