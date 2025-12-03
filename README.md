# simple-IAM-Policy-Analyzer
a very simple AWS IAM policy analyzer
for python 3.8+. 
The code reads policies from both bad.json and good.json and put them in the same list
and then it checks for four things in each policy:


1-Resource Wildcard

2-Action Wildcard

3-Privilege Escalation

4-Senstive Actions without condtions 


then it prints the if a policy has one of these things with its ID


The Expected output from the provided files is :


<img width="802" height="156" alt="image" src="https://github.com/user-attachments/assets/0bb8c03b-5f18-4dd7-939c-e4c4465a94f4" />
