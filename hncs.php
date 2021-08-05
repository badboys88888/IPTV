<?php
$id=$_GET[id];
$url = 'https://1812501212048408.cn-hangzhou.fc.aliyuncs.com/2016-08-15/proxy/node-api.online/node-api/tv/channelInfo?id='.$id;
$data = file_get_contents($url);
preg_match('/playUrl":"(.*?)"/',$data,$m);
header('location:'.urldecode($m[1]));
?>