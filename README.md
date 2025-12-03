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
