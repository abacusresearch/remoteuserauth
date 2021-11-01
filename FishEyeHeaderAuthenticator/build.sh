#!/bin/bash
rm com/cenqua/fisheye/user/plugin/*.class
javac -cp "/opt/atlassian/fisheye/lib/*" com/cenqua/fisheye/user/plugin/FishEyeHeaderAuthenticator.java 
jar cf FishEyeHeaderAuthenticator.jar com/cenqua/fisheye/user/plugin/*.class
cp FishEyeHeaderAuthenticator.jar /var/atlassian/fisheye/lib/
