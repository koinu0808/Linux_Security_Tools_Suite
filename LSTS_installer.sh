#!/bin/bash

ERROR=0
echo "更新 apt 安裝套件"
sudo apt update
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo "安裝 WhatWeb"
sudo apt install whatweb -y
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo "安裝 Nmap"
sudo apt install nmap -y
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo "安裝 Hydra"
sudo apt install hydra -y
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo "安裝 sshpass"
sudo apt install sshpass -y
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo "安裝 Gobuster"
sudo apt install gobuster -y
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo "安裝 Exiftool"
sudo apt install exiftool -y
if [ $? -ne 0 ]; then
    ((ERROR++))
fi

echo

if [ $ERROR -eq 0 ]; then
    echo 安裝完畢，未發現安裝錯誤。
else
    echo 已安裝完畢，發現 $ERROR 個安裝錯誤。
fi
