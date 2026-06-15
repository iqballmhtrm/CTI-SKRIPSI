#!/bin/bash
systemctl start elasticsearch
systemctl start logstash
systemctl restart suricata
