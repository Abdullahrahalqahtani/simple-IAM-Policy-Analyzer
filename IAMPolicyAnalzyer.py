
import json

def listify(value):
    if isinstance(value, list):
        return value #if list already do nothing
    return [value]  #if not list then make it a list and return it 


def listifystmt(value):
    stmts = value["Statement"]
    if isinstance(stmts, list):
        return stmts
    return [stmts] #if there's a single statement it'll make it to list with a single item , because if we get multiple statements it'll be in a list already


def checkResourceWC(policies):
    for policy in policies:

        stmts = listifystmt(policy)
        # Loop through *each* statement
        for stmt in stmts:
            
            if stmt.get("Effect", "Allow") != "Allow": #in Deny wildcard is fine
                continue
            has_RWD = False
            resourcelist = listify(stmt.get("Resource", []))
            for resource in resourcelist:
                if resource =="*" or resource == "arn:aws:s3:::*":
                    has_RWD=True
            
            if has_RWD:
                    print("Bad policy (wildcard resource). SID:", stmt.get("Sid", "<No Sid>"))


def checkActionsWC(policies):
    for policy in policies:

        stmts = listifystmt(policy)
        # Loop through *each* statement
        for stmt in stmts:
            
            if stmt.get("Effect", "Allow") != "Allow": #in Deny wildcard is fine
                continue
            
            actionslist = listify(stmt.get("Action",[]))
            has_AWD = False
            for action in actionslist:
                if "*" in action:
                    has_AWD = True
            if has_AWD :
                print("Bad policy (wildcard action). SID:", stmt.get("Sid", "<No Sid>"))
                    
                
def checkActionsPE(policies):
    COMP_ACTS = {
        "ec2:RunInstances",
        "lambda:CreateFunction",
        "ecs:RunTask",
    }
    for policy in policies:

        stmts = listifystmt(policy)
        # Loop through *each* statement
        for stmt in stmts:
            
            if stmt.get("Effect", "Allow") != "Allow": #in Deny wildcard is fine
                continue
            
            actionslist = listify(stmt.get("Action",[]))
            
            has_passrole = False
            has_compute = False
            
            for action in actionslist:
                
                if action == "iam:PassRole" or action == "iam:*" or action == "*":
                    has_passrole = True
                    
                if action in COMP_ACTS or action=="*":
                    has_compute = True
                    
                    
            if has_passrole and has_compute:
                print("Possible privilege escalation (PassRole + compute). SID:", stmt.get("Sid", "<No Sid>"))


def checkSensitiveActionsNoCond(policies):
    SENS_ACTS = {
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:CreateAccessKey",
    }

    for policy in policies:
        stmts = listifystmt(policy)

        for stmt in stmts:
            if stmt.get("Effect", "Allow") != "Allow":
                continue

            actionslist = set(listify(stmt.get("Action", [])))

            # If no sensitive actions, skip
            if not (actionslist & SENS_ACTS):
                continue

            condition = stmt.get("Condition")
            if not condition:
                print("Sensitive IAM actions without any Condition. SID:",
                      stmt.get("Sid", "<No Sid>"))


def main():
    datalist = []
    with open("good.json") as f:
        datalist.append(json.load(f))
    with open("bad.json") as f:
        datalist.append(json.load(f))

    checkResourceWC(datalist)
    checkActionsWC(datalist)
    checkActionsPE(datalist)
    checkSensitiveActionsNoCond(datalist)
            
if __name__ == "__main__":
    main()
