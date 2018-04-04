import os

class XSSDetector:
    template_name = ""
    template_obj = None
    line_num = 0
    error_message = ""
    vulnerabilities = ["{%autoescapeoff%}","{%endautoescape%}","|safe",
                       "|mark_safe","|escape"]
    reason_messages = ["autoescape was off.","autoescape was off.",
                       "safe filter was used.","mark_safe filter was used.",
                       "escape filter was used."]

    def __init__(self, template_paths):
        for path in template_paths:
            template_name = os.path.split(path)[-1]
            self.template_obj = open(path,"r")
            self.iterateLines(open(path,"r"))


    def addErrorMessage(self,message):
        if self.error_message == "":
            self.error_message = message
        else:
            self.error_message += message

    def makeArrow(self,index):
        result = ""
        for i in range(index):
            result += " "
        return result + "^\n"

    def createMessage(self,error, line, index):
        result = "WARNING: Your application may be at risk to an XSS attack.\n" + \
                'In template, "' + self.template_name + '", line ' + \
                str(self.line_num) + " the "  + error + "\n" + line.lstrip() + \
                self.makeArrow(index)
        return result

    def checkVulnerabilities(self, line):
        for i in range(len(self.vulnerabilities)):
            if self.vulnerabilities[i] in line.replace(" ", ""):
                index = line.lstrip().find(self.vulnerabilities[i])
                message = self.createMessage(self.reason_messages[i],line,index)
                self.addErrorMessage(message)

    def iterateLines(self):
        for line in self.template_obj:
            # Determine line number
            self.line_num += 1
            self.checkVulnerabilities(line)

    def getErrorMessages(self):
        return self.error_message


test = print(XSSDetector(templates))
